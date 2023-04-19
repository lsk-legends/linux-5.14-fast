// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>
#include <linux/freezer.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/psi.h>
#include <linux/kthread.h>
#include <linux/kswapsched.h>
#include <linux/mm_inline.h>
#include <linux/memcontrol.h>
#include <linux/delay.h>
#include <linux/rmap.h>
#include <linux/vmscan.h>
#include "internal.h"

#define WRITEBACK_CLUSTER_MAX 16UL

static unsigned int dedicated_cpu = 30;
static unsigned int max_reclaim_pages = 2048;
static unsigned int kswapsched_sleep_microsecs __read_mostly = 5;
static int kswapsched_sched_nice __read_mostly = 15;
static unsigned long kswapsched_sleep_expire;
static DECLARE_WAIT_QUEUE_HEAD(kswapsched_wait);
static DECLARE_RWSEM(kswapsched_sem);
static LIST_HEAD(kswapsched_list);

static bool cgroup_reclaim(struct scan_control *sc)
{
	return sc->target_mem_cgroup;
}

// writeback version of shrink_page_list()
static unsigned int writeback_page_list(struct list_head *page_list,
				     struct pglist_data *pgdat,
				     struct scan_control *sc)
{
	LIST_HEAD(ret_pages);
	unsigned int nr_reclaimed = 0;

	while (!list_empty(page_list)) {
		struct address_space *mapping;
		struct page *page;
		enum page_references references = PAGEREF_RECLAIM;
		unsigned int nr_pages;
		// swp_entry_t entry;

		page = lru_to_page(page_list);
		list_del(&page->lru);

		if (!trylock_page(page))
			goto keep;

		if (!page_mapped(page))
			goto keep_locked;

		VM_BUG_ON_PAGE(PageActive(page), page);

		nr_pages = compound_nr(page);
		sc->nr_scanned += nr_pages;

		if (unlikely(!page_evictable(page)))
			goto activate_locked;

		if (PageWriteback(page) || PageSwapCache(page) || PageSwapClean(page))
			goto keep_locked;

		if (!PageAnon(page) || !PageSwapBacked(page))
			goto keep_locked;
			
		references = page_check_references(page, sc);
		switch (references) {
		case PAGEREF_ACTIVATE:
			goto activate_locked;
		case PAGEREF_KEEP:
			goto keep_locked;
		case PAGEREF_RECLAIM:
		case PAGEREF_RECLAIM_CLEAN:
			; /* try to reclaim the page below */
		}

		if (page_maybe_dma_pinned(page))
			goto keep_locked;
		if (PageTransHuge(page))
			goto activate_locked;		

		// entry = get_swap_page(page);
		// if (!entry.val)
		// 	goto activate_locked_split;
		// set_page_dirty(page);
		// set_page_private(page, entry.val);
		// SetPageSwapClean(page);
		// mapping = swap_address_space(entry);

		if (!add_to_swap(page))
			goto activate_locked_split;
		mapping = page_mapping(page);
		ClearPageSwapCache(page);
		SetPageSwapClean(page);

		nr_reclaimed += nr_pages;

		if (page_mapped(page)) {
			/* unset ptes and shootdown TLBs */
			if (!try_to_unset(page)) {
				printk("try_to_unset failed\n");
				ClearPageSwapClean(page);
				SetPageSwapCache(page);
				goto activate_locked;
			}
		}

		if (!PageDirty(page))
			goto keep_locked;

		if (references == PAGEREF_RECLAIM_CLEAN)
			goto keep_locked;

		try_to_unmap_flush_dirty();
		switch (pageout(page, mapping)) {
		case PAGE_KEEP:
		case PAGE_CLEAN:
			goto keep_locked;
		case PAGE_ACTIVATE:
			goto activate_locked;
		case PAGE_SUCCESS:
			goto keep;
		}

		goto keep_locked;
activate_locked_split:
		if (nr_pages > 1)
			sc->nr_scanned -= (nr_pages - 1);

activate_locked:
		VM_BUG_ON_PAGE(PageActive(page), page);
		if (!PageMlocked(page))
			SetPageActive(page);
keep_locked:
		unlock_page(page);
keep:
		list_add(&page->lru, &ret_pages);
		VM_BUG_ON_PAGE(PageLRU(page) || PageUnevictable(page), page);
	}

	list_splice(&ret_pages, page_list);

	return nr_reclaimed;
}


static int too_many_isolated(struct pglist_data *pgdat)
{
	unsigned long inactive = node_page_state(pgdat, NR_INACTIVE_ANON);
	unsigned long isolated = node_page_state(pgdat, NR_ISOLATED_ANON);
	inactive >>= 3;
	return isolated > inactive;
}

static noinline_for_stack unsigned long
writeback_inactive_list(unsigned long nr_to_scan, struct lruvec *lruvec,
		     struct scan_control *sc, enum lru_list lru)
{
	LIST_HEAD(page_list);
	unsigned long nr_scanned;
	unsigned int nr_reclaimed = 0;
	unsigned long nr_taken;
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	bool stalled = false;

	while (unlikely(too_many_isolated(pgdat))) {
		if (stalled)
			return 0;
		msleep(100);
		stalled = true;
	}

	lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &page_list,
				     &nr_scanned, sc, lru);
	spin_unlock_irq(&lruvec->lru_lock);

	if (nr_taken == 0)
		return 0;

	nr_reclaimed = writeback_page_list(&page_list, pgdat, sc);

	spin_lock_irq(&lruvec->lru_lock);
	move_pages_to_lru(lruvec, &page_list);
	spin_unlock_irq(&lruvec->lru_lock);

	return nr_reclaimed;
}

static void get_scan_count(struct lruvec *lruvec, struct scan_control *sc,
			   unsigned long *nr)
{
	struct mem_cgroup *memcg = lruvec_memcg(lruvec);
	int swappiness = mem_cgroup_swappiness(memcg);
	enum lru_list lru = LRU_INACTIVE_ANON;
	unsigned long lruvec_size;
	unsigned long scan, protection;
	if ((cgroup_reclaim(sc) && !swappiness) || sc->cache_trim_mode){
		nr[lru] = 0;
		return;
	}

	lruvec_size = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);
	protection = mem_cgroup_protection(sc->target_mem_cgroup,
						memcg,
						sc->memcg_low_reclaim);

	if (protection) {
		unsigned long cgroup_size = mem_cgroup_size(memcg);

		/* Avoid TOCTOU with earlier protection check */
		cgroup_size = max(cgroup_size, protection);

		scan = lruvec_size - lruvec_size * protection /
			cgroup_size;

		scan = max(scan, WRITEBACK_CLUSTER_MAX);
	} else {
		scan = lruvec_size;
	}

	scan >>= sc->priority;

	if (!scan && !mem_cgroup_online(memcg))
		scan = min(lruvec_size, WRITEBACK_CLUSTER_MAX);

	nr[lru] = scan;
}

static void writeback_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];
	unsigned long nr_to_scan;
	enum lru_list lru = LRU_INACTIVE_ANON;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_to_reclaim = sc->nr_to_reclaim;
	
	get_scan_count(lruvec, sc, nr);
	
	while (nr[lru]) {
		nr_to_scan = min(nr[lru], WRITEBACK_CLUSTER_MAX);
		nr[lru] -= nr_to_scan;
		nr_reclaimed += writeback_inactive_list(nr_to_scan, lruvec, sc, lru);

		if (nr_reclaimed >= nr_to_reclaim)
			break;
	}

	sc->nr_reclaimed += nr_reclaimed;
	//count_memcg_events(sc->target_mem_cgroup, EAGER_WRITEBACK, nr_reclaimed);
	atomic_long_add(nr_reclaimed, &(sc->target_mem_cgroup->clean_anon));
}

static void writeback_zones(struct zonelist *zonelist, struct scan_control *sc)
{
	struct zoneref *z;
	struct zone *zone;
	pg_data_t *last_pgdat = NULL;
	struct mem_cgroup *target_memcg = sc->target_mem_cgroup;
	struct mem_cgroup *memcg = NULL;

	for_each_zone_zonelist_nodemask(zone, z, zonelist, sc->reclaim_idx, sc->nodemask) {
		if (zone->zone_pgdat == last_pgdat)
			continue;
		last_pgdat = zone->zone_pgdat;

		memcg = NULL;
		while ((memcg = mem_cgroup_iter(target_memcg, memcg, NULL))) {
			mem_cgroup_calculate_protection(target_memcg, memcg);
			if (mem_cgroup_below_min(memcg) || mem_cgroup_below_low(memcg))
				continue;

			writeback_lruvec(mem_cgroup_lruvec(memcg, last_pgdat), sc);
		}
	}
}

static void writeback_mem_cgroup_pages(struct mem_cgroup *target_memcg)
{
	struct scan_control sc = {
		.nr_to_reclaim = max_reclaim_pages,
		.gfp_mask = GFP_KERNEL | GFP_HIGHUSER_MOVABLE,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.target_mem_cgroup = target_memcg,
		.priority = DEF_PRIORITY,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
	};
	struct zonelist *zonelist = node_zonelist(numa_node_id(), sc.gfp_mask);

	do {
		sc.nr_scanned = 0;
		writeback_zones(zonelist, &sc);

		if (sc.nr_reclaimed >= sc.nr_to_reclaim)
			break;
	} while (--sc.priority >= 0);
}

static void kswapsched_list_add(struct task_struct *tsk)
{
	struct task_node *tnode;
	tnode = kmalloc(sizeof(*tnode), GFP_KERNEL);
	tnode->tsk = tsk;

    down_write(&kswapsched_sem);
	list_add(&tnode->node, &kswapsched_list);
    up_write(&kswapsched_sem);
}

static void kswapsched_list_del(struct task_struct *tsk)
{
	struct task_node *tnode, *n;
    down_write(&kswapsched_sem);
	list_for_each_entry_safe(tnode, n, &kswapsched_list, node) {
		if (tnode->tsk == tsk) {
			list_del(&tnode->node);
			kfree(tnode);
			break;
		}
	}
    up_write(&kswapsched_sem);
}

void kswapsched_list_set_affinity(unsigned int cpu)
{
	struct task_node *tnode;
	down_write(&kswapsched_sem);
	list_for_each_entry(tnode, &kswapsched_list, node) {
		set_cpus_allowed_ptr(tnode->tsk, cpumask_of(cpu));
	}
    up_write(&kswapsched_sem);
}

static bool kswapsched_should_wakeup(void)
{
	return kthread_should_stop() ||
	       time_after_eq(jiffies, kswapsched_sleep_expire);
}

static void kswapsched_do_sched(struct mem_cgroup *memcg)
{
	//unsigned long adc_flag = (1UL << ADC_PROFILE_OFFPATH_BIT);

	if ((page_counter_read(&memcg->memory) > READ_ONCE(memcg->writeback_high))
		&& (atomic_long_read(&memcg->clean_anon) < max_reclaim_pages)) {
		//count_memcg_events(memcg, GCTHREADS_SCHED, 1);
		writeback_mem_cgroup_pages(memcg);
	}
}

static void kswapsched_sleep(void)
{
	const unsigned long sleep_jiffies =
		usecs_to_jiffies(kswapsched_sleep_microsecs);

	kswapsched_sleep_expire = jiffies + sleep_jiffies;
	wait_event_freezable_timeout(kswapsched_wait,
						kswapsched_should_wakeup(),
						sleep_jiffies);
}

static int kswapsched(void *data)
{
	struct mem_cgroup *memcg = (struct mem_cgroup*)data;
	for ( ; ; ) {
		if (kthread_should_stop())
			break;

		kswapsched_do_sched(memcg);

		if (kswapsched_sleep_microsecs > 0)
			kswapsched_sleep();
		else
			cond_resched(); // avoid cpu soft lockup
	}

	return 0;
}

int kswapsched_init(struct mem_cgroup *memcg)
{
	int err = 0;
	struct task_struct *tsk;
	const char* fname;

	if (memcg->kswapsched)
		return 0;

	if (mem_cgroup_is_root(memcg))
		fname = "root";
	else
		fname = memcg->css.cgroup->kn->name;

	tsk = __kthread_create_on_cpu(kswapsched, memcg, dedicated_cpu,
				"kssd:%s", fname);
	if (IS_ERR(tsk)) {
		pr_err("Failed to start kswapsched for memcg %s\n", fname);
		err = PTR_ERR(tsk);
		goto out;
	}

	kswapsched_list_add(tsk);
	memcg->kswapsched = tsk;
	wake_up_process(tsk);

out:
	return err;
}

void kswapsched_destroy(struct mem_cgroup *memcg)
{
	struct task_struct *tsk = memcg->kswapsched;
	if (!tsk) return;

	memcg->kswapsched = NULL;
	kswapsched_list_del(tsk);
	kthread_stop(tsk);
}

#ifdef CONFIG_SYSFS
static ssize_t dedicated_cpu_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	ssize_t ret = sprintf(buf, "%u\n", dedicated_cpu);
	return ret;
}

static ssize_t dedicated_cpu_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned int value;
	if (kstrtouint(buf, 10, &value))
		return -EINVAL;

	dedicated_cpu = value;
	kswapsched_list_set_affinity(value);
	return count;
}

static struct kobj_attribute dedicated_cpu_attr =
	__ATTR(dedicated_cpu, 0644, dedicated_cpu_show, dedicated_cpu_store);

static ssize_t max_reclaim_pages_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	ssize_t ret = sprintf(buf, "%u\n", max_reclaim_pages);
	return ret;
}

static ssize_t max_reclaim_pages_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned int value;
	if (kstrtouint(buf, 10, &value))
		return -EINVAL;

	max_reclaim_pages = value;
	return count;
}

static struct kobj_attribute max_reclaim_pages_attr =
	__ATTR(max_reclaim_pages, 0644,
		   max_reclaim_pages_show, max_reclaim_pages_store);

static ssize_t sleep_microsecs_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	ssize_t ret = sprintf(buf, "%u\n", kswapsched_sleep_microsecs);
	return ret;
}

static ssize_t sleep_microsecs_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned int usecs;
	int err;
	
	err = kstrtouint(buf, 10, &usecs);
	if (err)
		return -EINVAL;

	kswapsched_sleep_microsecs = usecs;
	kswapsched_sleep_expire = 0;
	wake_up_interruptible(&kswapsched_wait);

	return count;
}

static struct kobj_attribute sleep_microsecs_attr =
	__ATTR(sleep_microsecs, 0644,
		   sleep_microsecs_show, sleep_microsecs_store);

static ssize_t sched_nice_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	ssize_t ret = sprintf(buf, "%d\n", kswapsched_sched_nice);
	return ret;
}

static ssize_t sched_nice_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	int err, nice;
	
	err = kstrtoint(buf, 10, &nice);
	if (err || nice < MIN_NICE || nice > MAX_NICE)
		return -EINVAL;
	
	kswapsched_sched_nice = nice;
	return count;
}

static struct kobj_attribute sched_nice_attr =
	__ATTR(sched_nice, 0644,
		   sched_nice_show, sched_nice_store);

static struct attribute *kswapsched_attr[] = {
	&max_reclaim_pages_attr.attr,
	&dedicated_cpu_attr.attr,
	&sleep_microsecs_attr.attr,
	&sched_nice_attr.attr,
	NULL,
};

struct attribute_group kswapsched_attr_group = {
	.attrs = kswapsched_attr,
};

static int __init kswapsched_init_sysfs(struct kobject **kswapsched_kobj)
{
	int err;

	*kswapsched_kobj = kobject_create_and_add("kswapsched", mm_kobj);
	if (unlikely(!*kswapsched_kobj)) {
		pr_err("failed to create kswapsched kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(*kswapsched_kobj, &kswapsched_attr_group);
	if (err) {
		pr_err("failed to register kswapsched_kobj group\n");
		goto delete_obj;
	}

	return 0;

delete_obj:
	kobject_put(*kswapsched_kobj);
	return err;
}

#else 
static int __init kswapsched_init_sysfs(struct kobject **kswapsched_kobj)
{
	return 0;
}
#endif

static int __init kswapsched_subsys_init(void)
{
	int err;
	struct kobject *kswapsched_kobj;

	err = kswapsched_init_sysfs(&kswapsched_kobj);
	if (err)
		return err;

	return 0;
}
subsys_initcall(kswapsched_subsys_init);
