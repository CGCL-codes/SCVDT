static void perf_callchain_user_64(struct perf_callchain_entry *entry,
				   struct pt_regs *regs)
{
	unsigned long sp, next_sp;
	unsigned long next_ip;
	unsigned long lr;
	long level = 0;
	struct signal_frame_64 __user *sigframe;
	unsigned long __user *fp, *uregs;

	next_ip = perf_instruction_pointer(regs);
	lr = regs->link;
	sp = regs->gpr[1];
	perf_callchain_store(entry, next_ip);

	for (;;) {
		fp = (unsigned long __user *) sp;
		if (!valid_user_sp(sp, 1) || read_user_stack_64(fp, &next_sp))
			return;
		if (level > 0 && read_user_stack_64(&fp[2], &next_ip))
			return;

		/*
		 * Note: the next_sp - sp >= signal frame size check
		 * is true when next_sp < sp, which can happen when
		 * transitioning from an alternate signal stack to the
		 * normal stack.
		 */
		if (next_sp - sp >= sizeof(struct signal_frame_64) &&
		    (is_sigreturn_64_address(next_ip, sp) ||
		     (level <= 1 && is_sigreturn_64_address(lr, sp))) &&
		    sane_signal_64_frame(sp)) {
			/*
			 * This looks like an signal frame
			 */
			sigframe = (struct signal_frame_64 __user *) sp;
			uregs = sigframe->uc.uc_mcontext.gp_regs;
			if (read_user_stack_64(&uregs[PT_NIP], &next_ip) ||
			    read_user_stack_64(&uregs[PT_LNK], &lr) ||
			    read_user_stack_64(&uregs[PT_R1], &sp))
				return;
			level = 0;
			perf_callchain_store(entry, PERF_CONTEXT_USER);
			perf_callchain_store(entry, next_ip);
			continue;
		}

		if (level == 0)
			next_ip = lr;
		perf_callchain_store(entry, next_ip);
		++level;
		sp = next_sp;
	}
}
