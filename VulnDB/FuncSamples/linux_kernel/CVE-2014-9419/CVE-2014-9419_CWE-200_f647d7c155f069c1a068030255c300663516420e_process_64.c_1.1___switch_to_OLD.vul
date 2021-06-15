__visible __notrace_funcgraph struct task_struct *
__switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread;
	struct thread_struct *next = &next_p->thread;
	int cpu = smp_processor_id();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);
	unsigned fsindex, gsindex;
	fpu_switch_t fpu;

	fpu = switch_fpu_prepare(prev_p, next_p, cpu);

	/*
	 * Reload esp0, LDT and the page table pointer:
	 */
	load_sp0(tss, next);

	/*
	 * Switch DS and ES.
	 * This won't pick up thread selector changes, but I guess that is ok.
	 */
	savesegment(es, prev->es);
	if (unlikely(next->es | prev->es))
		loadsegment(es, next->es);

	savesegment(ds, prev->ds);
	if (unlikely(next->ds | prev->ds))
		loadsegment(ds, next->ds);


	/* We must save %fs and %gs before load_TLS() because
	 * %fs and %gs may be cleared by load_TLS().
	 *
	 * (e.g. xen_load_tls())
	 */
	savesegment(fs, fsindex);
	savesegment(gs, gsindex);

	load_TLS(next, cpu);

	/*
	 * Leave lazy mode, flushing any hypercalls made here.
	 * This must be done before restoring TLS segments so
	 * the GDT and LDT are properly updated, and must be
	 * done before math_state_restore, so the TS bit is up
	 * to date.
	 */
	arch_end_context_switch(next_p);

	/*
	 * Switch FS and GS.
	 *
	 * Segment register != 0 always requires a reload.  Also
	 * reload when it has changed.  When prev process used 64bit
	 * base always reload to avoid an information leak.
	 */
	if (unlikely(fsindex | next->fsindex | prev->fs)) {
		loadsegment(fs, next->fsindex);
		/*
		 * Check if the user used a selector != 0; if yes
		 *  clear 64bit base, since overloaded base is always
		 *  mapped to the Null selector
		 */
		if (fsindex)
			prev->fs = 0;
	}
	/* when next process has a 64bit base use it */
	if (next->fs)
		wrmsrl(MSR_FS_BASE, next->fs);
	prev->fsindex = fsindex;

	if (unlikely(gsindex | next->gsindex | prev->gs)) {
		load_gs_index(next->gsindex);
		if (gsindex)
			prev->gs = 0;
	}
	if (next->gs)
		wrmsrl(MSR_KERNEL_GS_BASE, next->gs);
	prev->gsindex = gsindex;

	switch_fpu_finish(next_p, fpu);

	/*
	 * Switch the PDA and FPU contexts.
	 */
	prev->usersp = this_cpu_read(old_rsp);
	this_cpu_write(old_rsp, next->usersp);
	this_cpu_write(current_task, next_p);

	/*
	 * If it were not for PREEMPT_ACTIVE we could guarantee that the
	 * preempt_count of all tasks was equal here and this would not be
	 * needed.
	 */
	task_thread_info(prev_p)->saved_preempt_count = this_cpu_read(__preempt_count);
	this_cpu_write(__preempt_count, task_thread_info(next_p)->saved_preempt_count);

	this_cpu_write(kernel_stack,
		  (unsigned long)task_stack_page(next_p) +
		  THREAD_SIZE - KERNEL_STACK_OFFSET);

	/*
	 * Now maybe reload the debug registers and handle I/O bitmaps
	 */
	if (unlikely(task_thread_info(next_p)->flags & _TIF_WORK_CTXSW_NEXT ||
		     task_thread_info(prev_p)->flags & _TIF_WORK_CTXSW_PREV))
		__switch_to_xtra(prev_p, next_p, tss);

	return prev_p;
}
