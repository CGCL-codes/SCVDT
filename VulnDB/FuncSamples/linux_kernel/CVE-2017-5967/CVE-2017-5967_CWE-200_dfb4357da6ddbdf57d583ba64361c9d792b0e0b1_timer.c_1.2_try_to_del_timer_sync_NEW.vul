int try_to_del_timer_sync(struct timer_list *timer)
{
	struct timer_base *base;
	unsigned long flags;
	int ret = -1;

	debug_assert_init(timer);

	base = lock_timer_base(timer, &flags);

	if (base->running_timer != timer)
		ret = detach_if_pending(timer, base, true);

	spin_unlock_irqrestore(&base->lock, flags);

	return ret;
}
