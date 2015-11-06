/*
 *  TLB flush routines for radix kernels.
 *
 *  Copyright (C) 2015 Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/memblock.h>

#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/book3s/64/mmu-radix.h>

static DEFINE_RAW_SPINLOCK(native_tlbie_lock);

#ifndef CONFIG_PPC_STD_MMU_64 /* How to handle this ? */
struct mmu_psize_def mmu_psize_defs[MMU_PAGE_COUNT] = {
	[MMU_PAGE_64K] = {
		.shift	= 16,
		.sllp	= 5, /* Based on the SLBE {L||LP} encoding*/
	},
};
#endif

static inline void _tlbiel_pid(unsigned long pid)
{
	unsigned long rb,rs,ric,prs,r;

	rb = PPC_BIT(53); /* IS = 1 */
	rs = ((unsigned long)pid) << PPC_BITLSHIFT(31);
	prs = 1; /* process scoped */
	r = 1;   /* raidx format */
	ric = 2;  /* invalidate all the caches */

	asm volatile("ptesync": : :"memory");
	asm volatile(".long 0x7c000224 | (%0 << 11) | (%1 << 16) |"
		     "(%2 << 17) | (%3 << 18) | (%4 << 21)"
		     : : "r"(rb), "i"(r), "i"(prs), "i"(ric), "r"(rs) : "memory");
	asm volatile("ptesync": : :"memory");
}


static inline void _tlbie_pid(unsigned long pid)
{
	unsigned long rb,rs,ric,prs,r;

	rb = PPC_BIT(53); /* IS = 1 */
	rs = pid << PPC_BITLSHIFT(31);
	prs = 1; /* process scoped */
	r = 1;   /* raidx format */
	ric = 2;  /* invalidate all the caches */

	asm volatile("ptesync": : :"memory");
	asm volatile(".long 0x7c000264 | (%0 << 11) | (%1 << 16) |"
		     "(%2 << 17) | (%3 << 18) | (%4 << 21)"
		     : : "r"(rb), "i"(r), "i"(prs), "i"(ric), "r"(rs) : "memory");
	asm volatile("eieio; tlbsync; ptesync": : :"memory");
}

static inline void _tlbiel_va(unsigned long va, unsigned long pid,
			      unsigned long tsize)
{
	unsigned long rb,rs,ric,prs,r;

	rb = va & ~(PPC_BITMASK(52, 63));
	rb |= tsize << PPC_BITLSHIFT(58);
	rs = pid << PPC_BITLSHIFT(31);
	prs = 1; /* process scoped */
	r = 1;   /* raidx format */
	ric = 0;  /* not cluster bomb yet */

	asm volatile("ptesync": : :"memory");
	asm volatile(".long 0x7c000224 | (%0 << 11) | (%1 << 16) |"
		     "(%2 << 17) | (%3 << 18) | (%4 << 21)"
		     : : "r"(rb), "i"(r), "i"(prs), "i"(ric), "r"(rs) : "memory");
	asm volatile("ptesync": : :"memory");
}

static inline void _tlbie_va(unsigned long va, unsigned long pid,
			     unsigned long tsize)
{
	/* FIXME tsize and slb encoding */
	unsigned long rb,rs,ric,prs,r;

	rb = va & ~(PPC_BITMASK(52, 63));
	rb |= tsize << PPC_BITLSHIFT(58);
	rs = pid << PPC_BITLSHIFT(31);
	prs = 1; /* process scoped */
	r = 1;   /* raidx format */
	ric = 0;  /* no cluster bomb yet */

	asm volatile("ptesync": : :"memory");
	asm volatile(".long 0x7c000264 | (%0 << 11) | (%1 << 16) |"
		     "(%2 << 17) | (%3 << 18) | (%4 << 21)"
		     : : "r"(rb), "i"(r), "i"(prs), "i"(ric), "r"(rs) : "memory");
	asm volatile("eieio; tlbsync; ptesync": : :"memory");
}

/*
 * Base TLB flushing operations:
 *
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes kernel pages
 *
 *  - local_* variants of page and mm only apply to the current
 *    processor
 */
void local_flush_rtlb_mm(struct mm_struct *mm)
{
	unsigned int pid;

	preempt_disable();
	pid = mm->context.id;
	if (pid != MMU_NO_CONTEXT)
		_tlbiel_pid(pid);
	preempt_enable();
}
EXPORT_SYMBOL(local_flush_rtlb_mm);

void __local_flush_rtlb_page(struct mm_struct *mm, unsigned long vmaddr,
			    int tsize, int nid)
{
	unsigned int pid;

	preempt_disable();
	pid = mm ? mm->context.id : 0;
	if (pid != MMU_NO_CONTEXT)
		_tlbiel_va(vmaddr, pid, tsize);
	preempt_enable();
}

void local_flush_rtlb_page(struct vm_area_struct *vma, unsigned long vmaddr)
{
#ifdef CONFIG_HUGETLB_PAGE
	/* need the return fix for nohash.c */
	if (vma && is_vm_hugetlb_page(vma))
		return __local_flush_hugetlb_page(vma, vmaddr);
#endif
	__local_flush_rtlb_page(vma ? vma->vm_mm : NULL, vmaddr,
			       mmu_get_tsize(mmu_virtual_psize), 0);
}
EXPORT_SYMBOL(local_flush_rtlb_page);

#ifdef CONFIG_SMP
static int mm_is_core_local(struct mm_struct *mm)
{
	return cpumask_subset(mm_cpumask(mm),
			      topology_sibling_cpumask(smp_processor_id()));
}

void flush_rtlb_mm(struct mm_struct *mm)
{
	unsigned int pid;

	preempt_disable();
	pid = mm->context.id;
	if (unlikely(pid == MMU_NO_CONTEXT))
		goto no_context;

	if (!mm_is_core_local(mm)) {
		int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);

		if (lock_tlbie)
			raw_spin_lock(&native_tlbie_lock);
		_tlbie_pid(pid);
		if (lock_tlbie)
			raw_spin_unlock(&native_tlbie_lock);
	} else
		_tlbiel_pid(pid);
no_context:
	preempt_enable();
}
EXPORT_SYMBOL(flush_rtlb_mm);

void __flush_rtlb_page(struct mm_struct *mm, unsigned long vmaddr,
		       int tsize, int nid)
{
	unsigned int pid;

	preempt_disable();
	pid = mm ? mm->context.id : 0;
	if (unlikely(pid == MMU_NO_CONTEXT))
		goto bail;
	if (!mm_is_core_local(mm)) {
		int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);

		if (lock_tlbie)
			raw_spin_lock(&native_tlbie_lock);
		_tlbie_va(vmaddr, pid, tsize);
		if (lock_tlbie)
			raw_spin_unlock(&native_tlbie_lock);
	} else
		_tlbiel_va(vmaddr, pid, tsize);
bail:
	preempt_enable();
}

void flush_rtlb_page(struct vm_area_struct *vma, unsigned long vmaddr)
{
#ifdef CONFIG_HUGETLB_PAGE
	/* need the return fix for nohash.c */
	if (vma && is_vm_hugetlb_page(vma))
		return flush_hugetlb_page(vma, vmaddr);
#endif
	__flush_rtlb_page(vma ? vma->vm_mm : NULL, vmaddr,
			 mmu_get_tsize(mmu_virtual_psize), 0);
}
EXPORT_SYMBOL(flush_rtlb_page);

#endif /* CONFIG_SMP */

#define TLB_FLUSH_ALL -1UL
/*
 * Number of pages above which we will do a bcast tlbie. Just a
 * number at this point copied from x86
 */
static unsigned long tlb_single_page_flush_ceiling __read_mostly = 33;

static void __flush_rtlb_range(unsigned long pid, unsigned long start,
			       unsigned long end, int local)

{
	unsigned long addr;
	int tsize = mmu_get_tsize(mmu_virtual_psize);
	int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);
	/*
	 * use tlbiel for non-smp build
	 */
#ifndef CONFIG_SMP
	local = 1;
#endif
	preempt_disable();
	if (unlikely(pid == MMU_NO_CONTEXT))
		goto err_out;

	if (end == TLB_FLUSH_ALL ||
	    (end - start) > tlb_single_page_flush_ceiling * PAGE_SIZE) {
		if (local)
			_tlbiel_pid(pid);
		else
			_tlbie_pid(pid);
		goto err_out;
	}
	for (addr = start; addr < end; addr += PAGE_SIZE) {

		if (local)
			_tlbiel_va(addr, pid, tsize);
		else {
			if (lock_tlbie)
				raw_spin_lock(&native_tlbie_lock);
			_tlbie_va(addr, pid, tsize);
			if (lock_tlbie)
				raw_spin_unlock(&native_tlbie_lock);
		}
	}
err_out:
	preempt_enable();
}

void flush_rtlb_kernel_range(unsigned long start, unsigned long end)
{
	__flush_rtlb_range(0, start, end, 0);
}
EXPORT_SYMBOL(flush_rtlb_kernel_range);

/*
 * Currently, for range flushing, we just do a full mm flush. This should
 * be optimized based on a threshold on the size of the range, since
 * some implementation can stack multiple tlbivax before a tlbsync but
 * for now, we keep it that way
 */
void flush_rtlb_range(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end)

{
	struct mm_struct *mm = vma->vm_mm;
#ifdef CONFIG_SMP
	int local = mm_is_core_local(mm);
#else
	int local = 1;
#endif

	__flush_rtlb_range(mm->context.id, start, end, local);
}
EXPORT_SYMBOL(flush_rtlb_range);


void rtlb_flush(struct mmu_gather *tlb)
{
	struct mm_struct *mm = tlb->mm;
#ifdef CONFIG_SMP
	int local = mm_is_core_local(mm);
#else
	int local = 1;
#endif

	if (!tlb->fullmm && !tlb->need_flush_all)
		__flush_rtlb_range(mm->context.id, tlb->start, tlb->end, local);
	else
		flush_rtlb_mm(mm);
}
