static ssize_t driver_override_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	ssize_t len;

	device_lock(dev);
	len = sprintf(buf, "%s\n", pdev->driver_override);
	device_unlock(dev);
	return len;
}
