static int snd_ctl_elem_user_get(struct snd_kcontrol *kcontrol,
				 struct snd_ctl_elem_value *ucontrol)
{
	struct user_element *ue = kcontrol->private_data;

	mutex_lock(&ue->card->user_ctl_lock);
	memcpy(&ucontrol->value, ue->elem_data, ue->elem_data_size);
	mutex_unlock(&ue->card->user_ctl_lock);
	return 0;
}
