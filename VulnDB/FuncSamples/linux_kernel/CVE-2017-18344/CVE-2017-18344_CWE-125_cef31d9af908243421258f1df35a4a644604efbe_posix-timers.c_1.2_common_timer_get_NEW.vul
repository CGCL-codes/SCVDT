void common_timer_get(struct k_itimer *timr, struct itimerspec64 *cur_setting)
{
	const struct k_clock *kc = timr->kclock;
	ktime_t now, remaining, iv;
	struct timespec64 ts64;
	bool sig_none;

	sig_none = timr->it_sigev_notify == SIGEV_NONE;
	iv = timr->it_interval;

	/* interval timer ? */
	if (iv) {
		cur_setting->it_interval = ktime_to_timespec64(iv);
	} else if (!timr->it_active) {
		/*
		 * SIGEV_NONE oneshot timers are never queued. Check them
		 * below.
		 */
		if (!sig_none)
			return;
	}

	/*
	 * The timespec64 based conversion is suboptimal, but it's not
	 * worth to implement yet another callback.
	 */
	kc->clock_get(timr->it_clock, &ts64);
	now = timespec64_to_ktime(ts64);

	/*
	 * When a requeue is pending or this is a SIGEV_NONE timer move the
	 * expiry time forward by intervals, so expiry is > now.
	 */
	if (iv && (timr->it_requeue_pending & REQUEUE_PENDING || sig_none))
		timr->it_overrun += kc->timer_forward(timr, now);

	remaining = kc->timer_remaining(timr, now);
	/* Return 0 only, when the timer is expired and not pending */
	if (remaining <= 0) {
		/*
		 * A single shot SIGEV_NONE timer must return 0, when
		 * it is expired !
		 */
		if (!sig_none)
			cur_setting->it_value.tv_nsec = 1;
	} else {
		cur_setting->it_value = ktime_to_timespec64(remaining);
	}
}
