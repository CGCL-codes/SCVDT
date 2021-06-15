void giveup_all(struct task_struct *tsk)
{
	unsigned long usermsr;

	if (!tsk->thread.regs)
		return;

	check_if_tm_restore_required(tsk);

	usermsr = tsk->thread.regs->msr;

	if ((usermsr & msr_all_available) == 0)
		return;

	msr_check_and_set(msr_all_available);

	WARN_ON((usermsr & MSR_VSX) && !((usermsr & MSR_FP) && (usermsr & MSR_VEC)));

#ifdef CONFIG_PPC_FPU
	if (usermsr & MSR_FP)
		__giveup_fpu(tsk);
#endif
#ifdef CONFIG_ALTIVEC
	if (usermsr & MSR_VEC)
		__giveup_altivec(tsk);
#endif
#ifdef CONFIG_SPE
	if (usermsr & MSR_SPE)
		__giveup_spe(tsk);
#endif

	msr_check_and_clear(msr_all_available);
}
