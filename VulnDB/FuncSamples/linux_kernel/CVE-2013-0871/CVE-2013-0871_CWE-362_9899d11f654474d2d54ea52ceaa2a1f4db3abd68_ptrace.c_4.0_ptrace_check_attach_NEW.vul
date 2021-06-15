static int ptrace_check_attach(struct task_struct *child, bool ignore_state)
{
	int ret = -ESRCH;

	/*
	 * We take the read lock around doing both checks to close a
	 * possible race where someone else was tracing our child and
	 * detached between these two checks.  After this locked check,
	 * we are sure that this is our traced child and that can only
	 * be changed by us so it's not changing right after this.
	 */
	read_lock(&tasklist_lock);
	if (child->ptrace && child->parent == current) {
		WARN_ON(child->state == __TASK_TRACED);
		/*
		 * child->sighand can't be NULL, release_task()
		 * does ptrace_unlink() before __exit_signal().
		 */
		if (ignore_state || ptrace_freeze_traced(child))
			ret = 0;
	}
	read_unlock(&tasklist_lock);

	if (!ret && !ignore_state) {
		if (!wait_task_inactive(child, __TASK_TRACED)) {
			/*
			 * This can only happen if may_ptrace_stop() fails and
			 * ptrace_stop() changes ->state back to TASK_RUNNING,
			 * so we should not worry about leaking __TASK_TRACED.
			 */
			WARN_ON(child->state == __TASK_TRACED);
			ret = -ESRCH;
		}
	}

	return ret;
}
