static int uac_mixer_unit_get_channels(struct mixer_build *state,
				       struct uac_mixer_unit_descriptor *desc)
{
	int mu_channels;
	void *c;

	if (desc->bLength < sizeof(*desc))
		return -EINVAL;
	if (!desc->bNrInPins)
		return -EINVAL;

	switch (state->mixer->protocol) {
	case UAC_VERSION_1:
	case UAC_VERSION_2:
	default:
		if (desc->bLength < sizeof(*desc) + desc->bNrInPins + 1)
			return 0; /* no bmControls -> skip */
		mu_channels = uac_mixer_unit_bNrChannels(desc);
		break;
	case UAC_VERSION_3:
		mu_channels = get_cluster_channels_v3(state,
				uac3_mixer_unit_wClusterDescrID(desc));
		break;
	}

	if (!mu_channels)
		return 0;

	c = uac_mixer_unit_bmControls(desc, state->mixer->protocol);
	if (c - (void *)desc + (mu_channels - 1) / 8 >= desc->bLength)
		return 0; /* no bmControls -> skip */

	return mu_channels;
}
