int perf_cpu_time_max_percent_handler(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp,
				loff_t *ppos)
{
	int ret = proc_dointvec(table, write, buffer, lenp, ppos);

	if (ret || !write)
		return ret;

	if (sysctl_perf_cpu_time_max_percent == 100 ||
	    sysctl_perf_cpu_time_max_percent == 0) {
		printk(KERN_WARNING
		       "perf: Dynamic interrupt throttling disabled, can hang your system!\n");
		WRITE_ONCE(perf_sample_allowed_ns, 0);
	} else {
		update_perf_cpu_limits();
	}

	return 0;
}
