static int snd_timer_user_params(struct file *file,
				 struct snd_timer_params __user *_params)
{
	struct snd_timer_user *tu;
	struct snd_timer_params params;
	struct snd_timer *t;
	struct snd_timer_read *tr;
	struct snd_timer_tread *ttr;
	int err;

	tu = file->private_data;
	if (!tu->timeri)
		return -EBADFD;
	t = tu->timeri->timer;
	if (!t)
		return -EBADFD;
	if (copy_from_user(&params, _params, sizeof(params)))
		return -EFAULT;
	if (!(t->hw.flags & SNDRV_TIMER_HW_SLAVE) && params.ticks < 1) {
		err = -EINVAL;
		goto _end;
	}
	if (params.queue_size > 0 &&
	    (params.queue_size < 32 || params.queue_size > 1024)) {
		err = -EINVAL;
		goto _end;
	}
	if (params.filter & ~((1<<SNDRV_TIMER_EVENT_RESOLUTION)|
			      (1<<SNDRV_TIMER_EVENT_TICK)|
			      (1<<SNDRV_TIMER_EVENT_START)|
			      (1<<SNDRV_TIMER_EVENT_STOP)|
			      (1<<SNDRV_TIMER_EVENT_CONTINUE)|
			      (1<<SNDRV_TIMER_EVENT_PAUSE)|
			      (1<<SNDRV_TIMER_EVENT_SUSPEND)|
			      (1<<SNDRV_TIMER_EVENT_RESUME)|
			      (1<<SNDRV_TIMER_EVENT_MSTART)|
			      (1<<SNDRV_TIMER_EVENT_MSTOP)|
			      (1<<SNDRV_TIMER_EVENT_MCONTINUE)|
			      (1<<SNDRV_TIMER_EVENT_MPAUSE)|
			      (1<<SNDRV_TIMER_EVENT_MSUSPEND)|
			      (1<<SNDRV_TIMER_EVENT_MRESUME))) {
		err = -EINVAL;
		goto _end;
	}
	snd_timer_stop(tu->timeri);
	spin_lock_irq(&t->lock);
	tu->timeri->flags &= ~(SNDRV_TIMER_IFLG_AUTO|
			       SNDRV_TIMER_IFLG_EXCLUSIVE|
			       SNDRV_TIMER_IFLG_EARLY_EVENT);
	if (params.flags & SNDRV_TIMER_PSFLG_AUTO)
		tu->timeri->flags |= SNDRV_TIMER_IFLG_AUTO;
	if (params.flags & SNDRV_TIMER_PSFLG_EXCLUSIVE)
		tu->timeri->flags |= SNDRV_TIMER_IFLG_EXCLUSIVE;
	if (params.flags & SNDRV_TIMER_PSFLG_EARLY_EVENT)
		tu->timeri->flags |= SNDRV_TIMER_IFLG_EARLY_EVENT;
	spin_unlock_irq(&t->lock);
	if (params.queue_size > 0 &&
	    (unsigned int)tu->queue_size != params.queue_size) {
		if (tu->tread) {
			ttr = kmalloc(params.queue_size * sizeof(*ttr),
				      GFP_KERNEL);
			if (ttr) {
				kfree(tu->tqueue);
				tu->queue_size = params.queue_size;
				tu->tqueue = ttr;
			}
		} else {
			tr = kmalloc(params.queue_size * sizeof(*tr),
				     GFP_KERNEL);
			if (tr) {
				kfree(tu->queue);
				tu->queue_size = params.queue_size;
				tu->queue = tr;
			}
		}
	}
	tu->qhead = tu->qtail = tu->qused = 0;
	if (tu->timeri->flags & SNDRV_TIMER_IFLG_EARLY_EVENT) {
		if (tu->tread) {
			struct snd_timer_tread tread;
			memset(&tread, 0, sizeof(tread));
			tread.event = SNDRV_TIMER_EVENT_EARLY;
			tread.tstamp.tv_sec = 0;
			tread.tstamp.tv_nsec = 0;
			tread.val = 0;
			snd_timer_user_append_to_tqueue(tu, &tread);
		} else {
			struct snd_timer_read *r = &tu->queue[0];
			r->resolution = 0;
			r->ticks = 0;
			tu->qused++;
			tu->qtail++;
		}
	}
	tu->filter = params.filter;
	tu->ticks = params.ticks;
	err = 0;
 _end:
	if (copy_to_user(_params, &params, sizeof(params)))
		return -EFAULT;
	return err;
}
