// SPDX-License-Identifier: GPL-2.0-only

#ifndef _LINUX_KSWAPSCHED_H
#define _LINUX_KSWAPSCHED_H

#include <linux/list.h>

struct task_node {
	struct task_struct *tsk;
	struct list_head node;
};


int kswapsched_init(struct mem_cgroup *memcg);
void kswapsched_destroy(struct mem_cgroup *memcg);

#endif /*_LINUX_KSWAPSCHED_H*/