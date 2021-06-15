static int snd_seq_device_dev_free(struct snd_device *device)
{
	struct snd_seq_device *dev = device->device_data;

	put_device(&dev->dev);
	return 0;
}
