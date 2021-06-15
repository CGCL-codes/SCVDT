static ssize_t store_int_with_restart(struct device *s,
				      struct device_attribute *attr,
				      const char *buf, size_t size)
{
	unsigned long old_check_interval = check_interval;
	ssize_t ret = device_store_ulong(s, attr, buf, size);

	if (check_interval == old_check_interval)
		return ret;

	if (check_interval < 1)
		check_interval = 1;

	mutex_lock(&mce_sysfs_mutex);
	mce_restart();
	mutex_unlock(&mce_sysfs_mutex);

	return ret;
}
