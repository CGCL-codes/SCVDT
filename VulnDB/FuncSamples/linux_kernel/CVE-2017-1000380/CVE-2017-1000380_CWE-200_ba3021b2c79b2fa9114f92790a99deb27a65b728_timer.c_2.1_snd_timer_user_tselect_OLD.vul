static int snd_timer_user_tselect(struct file *file,
				  struct snd_timer_select __user *_tselect)
{
	struct snd_timer_user *tu;
	struct snd_timer_select tselect;
	char str[32];
	int err = 0;

	tu = file->private_data;
	if (tu->timeri) {
		snd_timer_close(tu->timeri);
		tu->timeri = NULL;
	}
	if (copy_from_user(&tselect, _tselect, sizeof(tselect))) {
		err = -EFAULT;
		goto __err;
	}
	sprintf(str, "application %i", current->pid);
	if (tselect.id.dev_class != SNDRV_TIMER_CLASS_SLAVE)
		tselect.id.dev_sclass = SNDRV_TIMER_SCLASS_APPLICATION;
	err = snd_timer_open(&tu->timeri, str, &tselect.id, current->pid);
	if (err < 0)
		goto __err;

	kfree(tu->queue);
	tu->queue = NULL;
	kfree(tu->tqueue);
	tu->tqueue = NULL;
	if (tu->tread) {
		tu->tqueue = kmalloc(tu->queue_size * sizeof(struct snd_timer_tread),
				     GFP_KERNEL);
		if (tu->tqueue == NULL)
			err = -ENOMEM;
	} else {
		tu->queue = kmalloc(tu->queue_size * sizeof(struct snd_timer_read),
				    GFP_KERNEL);
		if (tu->queue == NULL)
			err = -ENOMEM;
	}

      	if (err < 0) {
		snd_timer_close(tu->timeri);
      		tu->timeri = NULL;
      	} else {
		tu->timeri->flags |= SNDRV_TIMER_IFLG_FAST;
		tu->timeri->callback = tu->tread
			? snd_timer_user_tinterrupt : snd_timer_user_interrupt;
		tu->timeri->ccallback = snd_timer_user_ccallback;
		tu->timeri->callback_data = (void *)tu;
		tu->timeri->disconnect = snd_timer_user_disconnect;
	}

      __err:
	return err;
}
