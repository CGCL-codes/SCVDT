static int aac_compat_ioctl(struct scsi_device *sdev, int cmd, void __user *arg)
{
	struct aac_dev *dev = (struct aac_dev *)sdev->host->hostdata;
	return aac_compat_do_ioctl(dev, cmd, (unsigned long)arg);
}
