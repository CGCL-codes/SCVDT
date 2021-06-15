void __init init_timers(void)
{
	init_timer_cpus();
	open_softirq(TIMER_SOFTIRQ, run_timer_softirq);
}
