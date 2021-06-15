static int snd_ctl_tlv_ioctl(struct snd_ctl_file *file,
                             struct snd_ctl_tlv __user *_tlv,
                             int op_flag)
{
	struct snd_card *card = file->card;
	struct snd_ctl_tlv tlv;
	struct snd_kcontrol *kctl;
	struct snd_kcontrol_volatile *vd;
	unsigned int len;
	int err = 0;

	if (copy_from_user(&tlv, _tlv, sizeof(tlv)))
		return -EFAULT;
	if (tlv.length < sizeof(unsigned int) * 2)
		return -EINVAL;
	down_read(&card->controls_rwsem);
	kctl = snd_ctl_find_numid(card, tlv.numid);
	if (kctl == NULL) {
		err = -ENOENT;
		goto __kctl_end;
	}
	if (kctl->tlv.p == NULL) {
		err = -ENXIO;
		goto __kctl_end;
	}
	vd = &kctl->vd[tlv.numid - kctl->id.numid];
	if ((op_flag == 0 && (vd->access & SNDRV_CTL_ELEM_ACCESS_TLV_READ) == 0) ||
	    (op_flag > 0 && (vd->access & SNDRV_CTL_ELEM_ACCESS_TLV_WRITE) == 0) ||
	    (op_flag < 0 && (vd->access & SNDRV_CTL_ELEM_ACCESS_TLV_COMMAND) == 0)) {
	    	err = -ENXIO;
	    	goto __kctl_end;
	}
	if (vd->access & SNDRV_CTL_ELEM_ACCESS_TLV_CALLBACK) {
		if (vd->owner != NULL && vd->owner != file) {
			err = -EPERM;
			goto __kctl_end;
		}
		err = kctl->tlv.c(kctl, op_flag, tlv.length, _tlv->tlv);
		if (err > 0) {
			struct snd_ctl_elem_id id = kctl->id;
			up_read(&card->controls_rwsem);
			snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_TLV, &id);
			return 0;
		}
	} else {
		if (op_flag) {
			err = -ENXIO;
			goto __kctl_end;
		}
		len = kctl->tlv.p[1] + 2 * sizeof(unsigned int);
		if (tlv.length < len) {
			err = -ENOMEM;
			goto __kctl_end;
		}
		if (copy_to_user(_tlv->tlv, kctl->tlv.p, len))
			err = -EFAULT;
	}
      __kctl_end:
	up_read(&card->controls_rwsem);
	return err;
}
