static void snd_timer_user_tinterrupt(struct snd_timer_instance *timeri,
				      unsigned long resolution,
				      unsigned long ticks)
{
	struct snd_timer_user *tu = timeri->callback_data;
	struct snd_timer_tread *r, r1;
	struct timespec tstamp;
	int prev, append = 0;

	memset(&tstamp, 0, sizeof(tstamp));
	spin_lock(&tu->qlock);
	if ((tu->filter & ((1 << SNDRV_TIMER_EVENT_RESOLUTION) |
			   (1 << SNDRV_TIMER_EVENT_TICK))) == 0) {
		spin_unlock(&tu->qlock);
		return;
	}
	if (tu->last_resolution != resolution || ticks > 0) {
		if (timer_tstamp_monotonic)
			ktime_get_ts(&tstamp);
		else
			getnstimeofday(&tstamp);
	}
	if ((tu->filter & (1 << SNDRV_TIMER_EVENT_RESOLUTION)) &&
	    tu->last_resolution != resolution) {
		r1.event = SNDRV_TIMER_EVENT_RESOLUTION;
		r1.tstamp = tstamp;
		r1.val = resolution;
		snd_timer_user_append_to_tqueue(tu, &r1);
		tu->last_resolution = resolution;
		append++;
	}
	if ((tu->filter & (1 << SNDRV_TIMER_EVENT_TICK)) == 0)
		goto __wake;
	if (ticks == 0)
		goto __wake;
	if (tu->qused > 0) {
		prev = tu->qtail == 0 ? tu->queue_size - 1 : tu->qtail - 1;
		r = &tu->tqueue[prev];
		if (r->event == SNDRV_TIMER_EVENT_TICK) {
			r->tstamp = tstamp;
			r->val += ticks;
			append++;
			goto __wake;
		}
	}
	r1.event = SNDRV_TIMER_EVENT_TICK;
	r1.tstamp = tstamp;
	r1.val = ticks;
	snd_timer_user_append_to_tqueue(tu, &r1);
	append++;
      __wake:
	spin_unlock(&tu->qlock);
	if (append == 0)
		return;
	kill_fasync(&tu->fasync, SIGIO, POLL_IN);
	wake_up(&tu->qchange_sleep);
}
