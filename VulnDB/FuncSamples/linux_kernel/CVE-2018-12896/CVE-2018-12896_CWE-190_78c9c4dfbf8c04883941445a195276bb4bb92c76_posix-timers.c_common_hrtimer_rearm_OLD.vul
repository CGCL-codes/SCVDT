static void common_hrtimer_rearm(struct k_itimer *timr)
{
	struct hrtimer *timer = &timr->it.real.timer;

	if (!timr->it_interval)
		return;

	timr->it_overrun += (unsigned int) hrtimer_forward(timer,
						timer->base->get_time(),
						timr->it_interval);
	hrtimer_restart(timer);
}
