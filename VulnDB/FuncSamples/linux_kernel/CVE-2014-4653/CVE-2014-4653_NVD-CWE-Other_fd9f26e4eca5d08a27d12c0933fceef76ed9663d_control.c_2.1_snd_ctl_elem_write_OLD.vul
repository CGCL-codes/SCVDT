static int snd_ctl_elem_write(struct snd_card *card, struct snd_ctl_file *file,
			      struct snd_ctl_elem_value *control)
{
	struct snd_kcontrol *kctl;
	struct snd_kcontrol_volatile *vd;
	unsigned int index_offset;
	int result;

	down_read(&card->controls_rwsem);
	kctl = snd_ctl_find_id(card, &control->id);
	if (kctl == NULL) {
		result = -ENOENT;
	} else {
		index_offset = snd_ctl_get_ioff(kctl, &control->id);
		vd = &kctl->vd[index_offset];
		if (!(vd->access & SNDRV_CTL_ELEM_ACCESS_WRITE) ||
		    kctl->put == NULL ||
		    (file && vd->owner && vd->owner != file)) {
			result = -EPERM;
		} else {
			snd_ctl_build_ioff(&control->id, kctl, index_offset);
			result = kctl->put(kctl, control);
		}
		if (result > 0) {
			up_read(&card->controls_rwsem);
			snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE,
				       &control->id);
			return 0;
		}
	}
	up_read(&card->controls_rwsem);
	return result;
}
