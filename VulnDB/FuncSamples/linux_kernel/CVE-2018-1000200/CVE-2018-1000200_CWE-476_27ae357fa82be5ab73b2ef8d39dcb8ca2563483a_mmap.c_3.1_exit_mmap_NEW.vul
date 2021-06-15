void exit_mmap(struct mm_struct *mm)
{
	struct mmu_gather tlb;
	struct vm_area_struct *vma;
	unsigned long nr_accounted = 0;

	/* mm's last user has gone, and its about to be pulled down */
	mmu_notifier_release(mm);

	if (unlikely(mm_is_oom_victim(mm))) {
		/*
		 * Manually reap the mm to free as much memory as possible.
		 * Then, as the oom reaper does, set MMF_OOM_SKIP to disregard
		 * this mm from further consideration.  Taking mm->mmap_sem for
		 * write after setting MMF_OOM_SKIP will guarantee that the oom
		 * reaper will not run on this mm again after mmap_sem is
		 * dropped.
		 *
		 * Nothing can be holding mm->mmap_sem here and the above call
		 * to mmu_notifier_release(mm) ensures mmu notifier callbacks in
		 * __oom_reap_task_mm() will not block.
		 *
		 * This needs to be done before calling munlock_vma_pages_all(),
		 * which clears VM_LOCKED, otherwise the oom reaper cannot
		 * reliably test it.
		 */
		mutex_lock(&oom_lock);
		__oom_reap_task_mm(mm);
		mutex_unlock(&oom_lock);

		set_bit(MMF_OOM_SKIP, &mm->flags);
		down_write(&mm->mmap_sem);
		up_write(&mm->mmap_sem);
	}

	if (mm->locked_vm) {
		vma = mm->mmap;
		while (vma) {
			if (vma->vm_flags & VM_LOCKED)
				munlock_vma_pages_all(vma);
			vma = vma->vm_next;
		}
	}

	arch_exit_mmap(mm);

	vma = mm->mmap;
	if (!vma)	/* Can happen if dup_mmap() received an OOM */
		return;

	lru_add_drain();
	flush_cache_mm(mm);
	tlb_gather_mmu(&tlb, mm, 0, -1);
	/* update_hiwater_rss(mm) here? but nobody should be looking */
	/* Use -1 here to ensure all VMAs in the mm are unmapped */
	unmap_vmas(&tlb, vma, 0, -1);
	free_pgtables(&tlb, vma, FIRST_USER_ADDRESS, USER_PGTABLES_CEILING);
	tlb_finish_mmu(&tlb, 0, -1);

	/*
	 * Walk the list again, actually closing and freeing it,
	 * with preemption enabled, without holding any MM locks.
	 */
	while (vma) {
		if (vma->vm_flags & VM_ACCOUNT)
			nr_accounted += vma_pages(vma);
		vma = remove_vma(vma);
	}
	vm_unacct_memory(nr_accounted);
}
