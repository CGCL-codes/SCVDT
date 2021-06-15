asmlinkage long compat_sys_ptrace(compat_long_t request, compat_long_t pid,
				  compat_long_t addr, compat_long_t data)
{
	struct task_struct *child;
	long ret;

	if (request == PTRACE_TRACEME) {
		ret = ptrace_traceme();
		goto out;
	}

	child = ptrace_get_task_struct(pid);
	if (IS_ERR(child)) {
		ret = PTR_ERR(child);
		goto out;
	}

	if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
		ret = ptrace_attach(child, request, addr, data);
		/*
		 * Some architectures need to do book-keeping after
		 * a ptrace attach.
		 */
		if (!ret)
			arch_ptrace_attach(child);
		goto out_put_task_struct;
	}

	ret = ptrace_check_attach(child, request == PTRACE_KILL ||
				  request == PTRACE_INTERRUPT);
	if (!ret) {
		ret = compat_arch_ptrace(child, request, addr, data);
		if (ret || request != PTRACE_DETACH)
			ptrace_unfreeze_traced(child);
	}

 out_put_task_struct:
	put_task_struct(child);
 out:
	return ret;
}
