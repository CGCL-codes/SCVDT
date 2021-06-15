void start_cfs_bandwidth(struct cfs_bandwidth *cfs_b)
{
	u64 overrun;

	lockdep_assert_held(&cfs_b->lock);

	if (cfs_b->period_active)
		return;

	cfs_b->period_active = 1;
	overrun = hrtimer_forward_now(&cfs_b->period_timer, cfs_b->period);
	cfs_b->runtime_expires += (overrun + 1) * ktime_to_ns(cfs_b->period);
	cfs_b->expires_seq++;
	hrtimer_start_expires(&cfs_b->period_timer, HRTIMER_MODE_ABS_PINNED);
}
