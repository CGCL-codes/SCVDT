static int do_io_accounting(struct task_struct *task, char *buffer, int whole)
{
	struct task_io_accounting acct = task->ioac;
	unsigned long flags;

	if (whole && lock_task_sighand(task, &flags)) {
		struct task_struct *t = task;

		task_io_accounting_add(&acct, &task->signal->ioac);
		while_each_thread(task, t)
			task_io_accounting_add(&acct, &t->ioac);

		unlock_task_sighand(task, &flags);
	}
	return sprintf(buffer,
			"rchar: %llu\n"
			"wchar: %llu\n"
			"syscr: %llu\n"
			"syscw: %llu\n"
			"read_bytes: %llu\n"
			"write_bytes: %llu\n"
			"cancelled_write_bytes: %llu\n",
			(unsigned long long)acct.rchar,
			(unsigned long long)acct.wchar,
			(unsigned long long)acct.syscr,
			(unsigned long long)acct.syscw,
			(unsigned long long)acct.read_bytes,
			(unsigned long long)acct.write_bytes,
			(unsigned long long)acct.cancelled_write_bytes);
}
