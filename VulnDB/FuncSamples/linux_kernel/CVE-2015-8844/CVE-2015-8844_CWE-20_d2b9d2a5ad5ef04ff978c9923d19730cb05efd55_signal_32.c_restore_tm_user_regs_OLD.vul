static long restore_tm_user_regs(struct pt_regs *regs,
				 struct mcontext __user *sr,
				 struct mcontext __user *tm_sr)
{
	long err;
	unsigned long msr, msr_hi;
#ifdef CONFIG_VSX
	int i;
#endif

	/*
	 * restore general registers but not including MSR or SOFTE. Also
	 * take care of keeping r2 (TLS) intact if not a signal.
	 * See comment in signal_64.c:restore_tm_sigcontexts();
	 * TFHAR is restored from the checkpointed NIP; TEXASR and TFIAR
	 * were set by the signal delivery.
	 */
	err = restore_general_regs(regs, tm_sr);
	err |= restore_general_regs(&current->thread.ckpt_regs, sr);

	err |= __get_user(current->thread.tm_tfhar, &sr->mc_gregs[PT_NIP]);

	err |= __get_user(msr, &sr->mc_gregs[PT_MSR]);
	if (err)
		return 1;

	/* Restore the previous little-endian mode */
	regs->msr = (regs->msr & ~MSR_LE) | (msr & MSR_LE);

	/*
	 * Do this before updating the thread state in
	 * current->thread.fpr/vr/evr.  That way, if we get preempted
	 * and another task grabs the FPU/Altivec/SPE, it won't be
	 * tempted to save the current CPU state into the thread_struct
	 * and corrupt what we are writing there.
	 */
	discard_lazy_cpu_state();

#ifdef CONFIG_ALTIVEC
	regs->msr &= ~MSR_VEC;
	if (msr & MSR_VEC) {
		/* restore altivec registers from the stack */
		if (__copy_from_user(&current->thread.vr_state, &sr->mc_vregs,
				     sizeof(sr->mc_vregs)) ||
		    __copy_from_user(&current->thread.transact_vr,
				     &tm_sr->mc_vregs,
				     sizeof(sr->mc_vregs)))
			return 1;
	} else if (current->thread.used_vr) {
		memset(&current->thread.vr_state, 0,
		       ELF_NVRREG * sizeof(vector128));
		memset(&current->thread.transact_vr, 0,
		       ELF_NVRREG * sizeof(vector128));
	}

	/* Always get VRSAVE back */
	if (__get_user(current->thread.vrsave,
		       (u32 __user *)&sr->mc_vregs[32]) ||
	    __get_user(current->thread.transact_vrsave,
		       (u32 __user *)&tm_sr->mc_vregs[32]))
		return 1;
	if (cpu_has_feature(CPU_FTR_ALTIVEC))
		mtspr(SPRN_VRSAVE, current->thread.vrsave);
#endif /* CONFIG_ALTIVEC */

	regs->msr &= ~(MSR_FP | MSR_FE0 | MSR_FE1);

	if (copy_fpr_from_user(current, &sr->mc_fregs) ||
	    copy_transact_fpr_from_user(current, &tm_sr->mc_fregs))
		return 1;

#ifdef CONFIG_VSX
	regs->msr &= ~MSR_VSX;
	if (msr & MSR_VSX) {
		/*
		 * Restore altivec registers from the stack to a local
		 * buffer, then write this out to the thread_struct
		 */
		if (copy_vsx_from_user(current, &sr->mc_vsregs) ||
		    copy_transact_vsx_from_user(current, &tm_sr->mc_vsregs))
			return 1;
	} else if (current->thread.used_vsr)
		for (i = 0; i < 32 ; i++) {
			current->thread.fp_state.fpr[i][TS_VSRLOWOFFSET] = 0;
			current->thread.transact_fp.fpr[i][TS_VSRLOWOFFSET] = 0;
		}
#endif /* CONFIG_VSX */

#ifdef CONFIG_SPE
	/* SPE regs are not checkpointed with TM, so this section is
	 * simply the same as in restore_user_regs().
	 */
	regs->msr &= ~MSR_SPE;
	if (msr & MSR_SPE) {
		if (__copy_from_user(current->thread.evr, &sr->mc_vregs,
				     ELF_NEVRREG * sizeof(u32)))
			return 1;
	} else if (current->thread.used_spe)
		memset(current->thread.evr, 0, ELF_NEVRREG * sizeof(u32));

	/* Always get SPEFSCR back */
	if (__get_user(current->thread.spefscr, (u32 __user *)&sr->mc_vregs
		       + ELF_NEVRREG))
		return 1;
#endif /* CONFIG_SPE */

	/* Now, recheckpoint.  This loads up all of the checkpointed (older)
	 * registers, including FP and V[S]Rs.  After recheckpointing, the
	 * transactional versions should be loaded.
	 */
	tm_enable();
	/* Make sure the transaction is marked as failed */
	current->thread.tm_texasr |= TEXASR_FS;
	/* This loads the checkpointed FP/VEC state, if used */
	tm_recheckpoint(&current->thread, msr);
	/* Get the top half of the MSR */
	if (__get_user(msr_hi, &tm_sr->mc_gregs[PT_MSR]))
		return 1;
	/* Pull in MSR TM from user context */
	regs->msr = (regs->msr & ~MSR_TS_MASK) | ((msr_hi<<32) & MSR_TS_MASK);

	/* This loads the speculative FP/VEC state, if used */
	if (msr & MSR_FP) {
		do_load_up_transact_fpu(&current->thread);
		regs->msr |= (MSR_FP | current->thread.fpexc_mode);
	}
#ifdef CONFIG_ALTIVEC
	if (msr & MSR_VEC) {
		do_load_up_transact_altivec(&current->thread);
		regs->msr |= MSR_VEC;
	}
#endif

	return 0;
}
