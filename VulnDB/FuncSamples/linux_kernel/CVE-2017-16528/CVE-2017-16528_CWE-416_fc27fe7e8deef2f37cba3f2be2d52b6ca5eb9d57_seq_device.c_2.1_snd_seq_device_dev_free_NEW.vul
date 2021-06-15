static int snd_seq_device_dev_free(struct snd_device *device)
{
	struct snd_seq_device *dev = device->device_data;

	cancel_autoload_drivers();
	put_device(&dev->dev);
	return 0;
}
