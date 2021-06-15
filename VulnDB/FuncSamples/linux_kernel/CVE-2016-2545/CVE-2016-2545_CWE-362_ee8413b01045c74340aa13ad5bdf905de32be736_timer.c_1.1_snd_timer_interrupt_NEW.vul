void snd_timer_interrupt(struct snd_timer * timer, unsigned long ticks_left)
{
	struct snd_timer_instance *ti, *ts, *tmp;
	unsigned long resolution, ticks;
	struct list_head *p, *ack_list_head;
	unsigned long flags;
	int use_tasklet = 0;

	if (timer == NULL)
		return;

	spin_lock_irqsave(&timer->lock, flags);

	/* remember the current resolution */
	if (timer->hw.c_resolution)
		resolution = timer->hw.c_resolution(timer);
	else
		resolution = timer->hw.resolution;

	/* loop for all active instances
	 * Here we cannot use list_for_each_entry because the active_list of a
	 * processed instance is relinked to done_list_head before the callback
	 * is called.
	 */
	list_for_each_entry_safe(ti, tmp, &timer->active_list_head,
				 active_list) {
		if (!(ti->flags & SNDRV_TIMER_IFLG_RUNNING))
			continue;
		ti->pticks += ticks_left;
		ti->resolution = resolution;
		if (ti->cticks < ticks_left)
			ti->cticks = 0;
		else
			ti->cticks -= ticks_left;
		if (ti->cticks) /* not expired */
			continue;
		if (ti->flags & SNDRV_TIMER_IFLG_AUTO) {
			ti->cticks = ti->ticks;
		} else {
			ti->flags &= ~SNDRV_TIMER_IFLG_RUNNING;
			if (--timer->running)
				list_del_init(&ti->active_list);
		}
		if ((timer->hw.flags & SNDRV_TIMER_HW_TASKLET) ||
		    (ti->flags & SNDRV_TIMER_IFLG_FAST))
			ack_list_head = &timer->ack_list_head;
		else
			ack_list_head = &timer->sack_list_head;
		if (list_empty(&ti->ack_list))
			list_add_tail(&ti->ack_list, ack_list_head);
		list_for_each_entry(ts, &ti->slave_active_head, active_list) {
			ts->pticks = ti->pticks;
			ts->resolution = resolution;
			if (list_empty(&ts->ack_list))
				list_add_tail(&ts->ack_list, ack_list_head);
		}
	}
	if (timer->flags & SNDRV_TIMER_FLG_RESCHED)
		snd_timer_reschedule(timer, timer->sticks);
	if (timer->running) {
		if (timer->hw.flags & SNDRV_TIMER_HW_STOP) {
			timer->hw.stop(timer);
			timer->flags |= SNDRV_TIMER_FLG_CHANGE;
		}
		if (!(timer->hw.flags & SNDRV_TIMER_HW_AUTO) ||
		    (timer->flags & SNDRV_TIMER_FLG_CHANGE)) {
			/* restart timer */
			timer->flags &= ~SNDRV_TIMER_FLG_CHANGE;
			timer->hw.start(timer);
		}
	} else {
		timer->hw.stop(timer);
	}

	/* now process all fast callbacks */
	while (!list_empty(&timer->ack_list_head)) {
		p = timer->ack_list_head.next;		/* get first item */
		ti = list_entry(p, struct snd_timer_instance, ack_list);

		/* remove from ack_list and make empty */
		list_del_init(p);

		ticks = ti->pticks;
		ti->pticks = 0;

		ti->flags |= SNDRV_TIMER_IFLG_CALLBACK;
		spin_unlock(&timer->lock);
		if (ti->callback)
			ti->callback(ti, resolution, ticks);
		spin_lock(&timer->lock);
		ti->flags &= ~SNDRV_TIMER_IFLG_CALLBACK;
	}

	/* do we have any slow callbacks? */
	use_tasklet = !list_empty(&timer->sack_list_head);
	spin_unlock_irqrestore(&timer->lock, flags);

	if (use_tasklet)
		tasklet_schedule(&timer->task_queue);
}
