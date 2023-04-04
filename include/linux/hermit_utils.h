/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Declarations for Hermit functions in mm/hermit_utils.c
 */
#include <linux/swap.h>
#include <linux/mm_types.h>
#include <linux/swap_stats.h>
#include <linux/mm.h>
/***
 * util functions
 */

void hermit_faultin_page(struct vm_area_struct *vma,
		unsigned long addr, struct page * page, pte_t*pte, pte_t orig_pte);
