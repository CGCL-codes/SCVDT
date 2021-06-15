int del_timer(struct timer_list *timer)
{
	struct timer_base *base;
	unsigned long flags;
	int ret = 0;

	debug_assert_init(timer);

	if (timer_pending(timer)) {
		base = lock_timer_base(timer, &flags);
		ret = detach_if_pending(timer, base, true);
		spin_unlock_irqrestore(&base->lock, flags);
	}

	return ret;
}
