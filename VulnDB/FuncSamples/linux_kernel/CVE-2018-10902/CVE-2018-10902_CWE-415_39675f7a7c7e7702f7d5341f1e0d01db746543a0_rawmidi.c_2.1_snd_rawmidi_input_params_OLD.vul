int snd_rawmidi_input_params(struct snd_rawmidi_substream *substream,
			     struct snd_rawmidi_params * params)
{
	char *newbuf;
	struct snd_rawmidi_runtime *runtime = substream->runtime;

	snd_rawmidi_drain_input(substream);
	if (params->buffer_size < 32 || params->buffer_size > 1024L * 1024L) {
		return -EINVAL;
	}
	if (params->avail_min < 1 || params->avail_min > params->buffer_size) {
		return -EINVAL;
	}
	if (params->buffer_size != runtime->buffer_size) {
		newbuf = krealloc(runtime->buffer, params->buffer_size,
				  GFP_KERNEL);
		if (!newbuf)
			return -ENOMEM;
		runtime->buffer = newbuf;
		runtime->buffer_size = params->buffer_size;
	}
	runtime->avail_min = params->avail_min;
	return 0;
}
