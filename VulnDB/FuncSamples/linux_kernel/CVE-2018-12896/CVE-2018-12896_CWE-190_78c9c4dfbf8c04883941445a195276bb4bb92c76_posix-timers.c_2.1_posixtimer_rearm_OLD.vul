void posixtimer_rearm(struct siginfo *info)
{
	struct k_itimer *timr;
	unsigned long flags;

	timr = lock_timer(info->si_tid, &flags);
	if (!timr)
		return;

	if (timr->it_requeue_pending == info->si_sys_private) {
		timr->kclock->timer_rearm(timr);

		timr->it_active = 1;
		timr->it_overrun_last = timr->it_overrun;
		timr->it_overrun = -1;
		++timr->it_requeue_pending;

		info->si_overrun += timr->it_overrun_last;
	}

	unlock_timer(timr, flags);
}
