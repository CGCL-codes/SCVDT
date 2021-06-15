static int snd_ctl_elem_user_put(struct snd_kcontrol *kcontrol,
				 struct snd_ctl_elem_value *ucontrol)
{
	int change;
	struct user_element *ue = kcontrol->private_data;

	mutex_lock(&ue->card->user_ctl_lock);
	change = memcmp(&ucontrol->value, ue->elem_data, ue->elem_data_size) != 0;
	if (change)
		memcpy(ue->elem_data, &ucontrol->value, ue->elem_data_size);
	mutex_unlock(&ue->card->user_ctl_lock);
	return change;
}
