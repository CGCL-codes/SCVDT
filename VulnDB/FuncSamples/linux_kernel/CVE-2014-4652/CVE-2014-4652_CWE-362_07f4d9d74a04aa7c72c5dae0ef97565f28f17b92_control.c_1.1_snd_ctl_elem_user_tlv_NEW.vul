static int snd_ctl_elem_user_tlv(struct snd_kcontrol *kcontrol,
				 int op_flag,
				 unsigned int size,
				 unsigned int __user *tlv)
{
	struct user_element *ue = kcontrol->private_data;
	int change = 0;
	void *new_data;

	if (op_flag > 0) {
		if (size > 1024 * 128)	/* sane value */
			return -EINVAL;

		new_data = memdup_user(tlv, size);
		if (IS_ERR(new_data))
			return PTR_ERR(new_data);
		mutex_lock(&ue->card->user_ctl_lock);
		change = ue->tlv_data_size != size;
		if (!change)
			change = memcmp(ue->tlv_data, new_data, size);
		kfree(ue->tlv_data);
		ue->tlv_data = new_data;
		ue->tlv_data_size = size;
		mutex_unlock(&ue->card->user_ctl_lock);
	} else {
		int ret = 0;

		mutex_lock(&ue->card->user_ctl_lock);
		if (!ue->tlv_data_size || !ue->tlv_data) {
			ret = -ENXIO;
			goto err_unlock;
		}
		if (size < ue->tlv_data_size) {
			ret = -ENOSPC;
			goto err_unlock;
		}
		if (copy_to_user(tlv, ue->tlv_data, ue->tlv_data_size))
			ret = -EFAULT;
err_unlock:
		mutex_unlock(&ue->card->user_ctl_lock);
		if (ret)
			return ret;
	}
	return change;
}
