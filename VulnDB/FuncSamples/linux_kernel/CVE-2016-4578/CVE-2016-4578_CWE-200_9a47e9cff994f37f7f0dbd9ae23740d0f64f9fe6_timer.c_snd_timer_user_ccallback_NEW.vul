static void snd_timer_user_ccallback(struct snd_timer_instance *timeri,
				     int event,
				     struct timespec *tstamp,
				     unsigned long resolution)
{
	struct snd_timer_user *tu = timeri->callback_data;
	struct snd_timer_tread r1;
	unsigned long flags;

	if (event >= SNDRV_TIMER_EVENT_START &&
	    event <= SNDRV_TIMER_EVENT_PAUSE)
		tu->tstamp = *tstamp;
	if ((tu->filter & (1 << event)) == 0 || !tu->tread)
		return;
	memset(&r1, 0, sizeof(r1));
	r1.event = event;
	r1.tstamp = *tstamp;
	r1.val = resolution;
	spin_lock_irqsave(&tu->qlock, flags);
	snd_timer_user_append_to_tqueue(tu, &r1);
	spin_unlock_irqrestore(&tu->qlock, flags);
	kill_fasync(&tu->fasync, SIGIO, POLL_IN);
	wake_up(&tu->qchange_sleep);
}
