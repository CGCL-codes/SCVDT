int snd_timer_open(struct snd_timer_instance **ti,
		   char *owner, struct snd_timer_id *tid,
		   unsigned int slave_id)
{
	struct snd_timer *timer;
	struct snd_timer_instance *timeri = NULL;
	struct device *card_dev_to_put = NULL;
	int err;

	mutex_lock(&register_mutex);
	if (tid->dev_class == SNDRV_TIMER_CLASS_SLAVE) {
		/* open a slave instance */
		if (tid->dev_sclass <= SNDRV_TIMER_SCLASS_NONE ||
		    tid->dev_sclass > SNDRV_TIMER_SCLASS_OSS_SEQUENCER) {
			pr_debug("ALSA: timer: invalid slave class %i\n",
				 tid->dev_sclass);
			err = -EINVAL;
			goto unlock;
		}
		timeri = snd_timer_instance_new(owner, NULL);
		if (!timeri) {
			err = -ENOMEM;
			goto unlock;
		}
		timeri->slave_class = tid->dev_sclass;
		timeri->slave_id = tid->device;
		timeri->flags |= SNDRV_TIMER_IFLG_SLAVE;
		list_add_tail(&timeri->open_list, &snd_timer_slave_list);
		err = snd_timer_check_slave(timeri);
		if (err < 0) {
			snd_timer_close_locked(timeri, &card_dev_to_put);
			timeri = NULL;
		}
		goto unlock;
	}

	/* open a master instance */
	timer = snd_timer_find(tid);
#ifdef CONFIG_MODULES
	if (!timer) {
		mutex_unlock(&register_mutex);
		snd_timer_request(tid);
		mutex_lock(&register_mutex);
		timer = snd_timer_find(tid);
	}
#endif
	if (!timer) {
		err = -ENODEV;
		goto unlock;
	}
	if (!list_empty(&timer->open_list_head)) {
		timeri = list_entry(timer->open_list_head.next,
				    struct snd_timer_instance, open_list);
		if (timeri->flags & SNDRV_TIMER_IFLG_EXCLUSIVE) {
			err = -EBUSY;
			timeri = NULL;
			goto unlock;
		}
	}
	if (timer->num_instances >= timer->max_instances) {
		err = -EBUSY;
		goto unlock;
	}
	timeri = snd_timer_instance_new(owner, timer);
	if (!timeri) {
		err = -ENOMEM;
		goto unlock;
	}
	/* take a card refcount for safe disconnection */
	if (timer->card)
		get_device(&timer->card->card_dev);
	timeri->slave_class = tid->dev_sclass;
	timeri->slave_id = slave_id;

	if (list_empty(&timer->open_list_head) && timer->hw.open) {
		err = timer->hw.open(timer);
		if (err) {
			kfree(timeri->owner);
			kfree(timeri);
			timeri = NULL;

			if (timer->card)
				card_dev_to_put = &timer->card->card_dev;
			module_put(timer->module);
			goto unlock;
		}
	}

	list_add_tail(&timeri->open_list, &timer->open_list_head);
	timer->num_instances++;
	err = snd_timer_check_master(timeri);
	if (err < 0) {
		snd_timer_close_locked(timeri, &card_dev_to_put);
		timeri = NULL;
	}

 unlock:
	mutex_unlock(&register_mutex);
	/* put_device() is called after unlock for avoiding deadlock */
	if (card_dev_to_put)
		put_device(card_dev_to_put);
	*ti = timeri;
	return err;
}
