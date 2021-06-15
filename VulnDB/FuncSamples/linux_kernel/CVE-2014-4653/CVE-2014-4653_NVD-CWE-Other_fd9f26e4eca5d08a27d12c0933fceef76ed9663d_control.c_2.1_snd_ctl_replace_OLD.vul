int snd_ctl_replace(struct snd_card *card, struct snd_kcontrol *kcontrol,
		    bool add_on_replace)
{
	struct snd_ctl_elem_id id;
	unsigned int idx;
	struct snd_kcontrol *old;
	int ret;

	if (!kcontrol)
		return -EINVAL;
	if (snd_BUG_ON(!card || !kcontrol->info)) {
		ret = -EINVAL;
		goto error;
	}
	id = kcontrol->id;
	down_write(&card->controls_rwsem);
	old = snd_ctl_find_id(card, &id);
	if (!old) {
		if (add_on_replace)
			goto add;
		up_write(&card->controls_rwsem);
		ret = -EINVAL;
		goto error;
	}
	ret = snd_ctl_remove(card, old);
	if (ret < 0) {
		up_write(&card->controls_rwsem);
		goto error;
	}
add:
	if (snd_ctl_find_hole(card, kcontrol->count) < 0) {
		up_write(&card->controls_rwsem);
		ret = -ENOMEM;
		goto error;
	}
	list_add_tail(&kcontrol->list, &card->controls);
	card->controls_count += kcontrol->count;
	kcontrol->id.numid = card->last_numid + 1;
	card->last_numid += kcontrol->count;
	up_write(&card->controls_rwsem);
	for (idx = 0; idx < kcontrol->count; idx++, id.index++, id.numid++)
		snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_ADD, &id);
	return 0;

error:
	snd_ctl_free_one(kcontrol);
	return ret;
}
