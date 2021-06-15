static ssize_t store_int_with_restart(struct device *s,
				      struct device_attribute *attr,
				      const char *buf, size_t size)
{
	ssize_t ret = device_store_int(s, attr, buf, size);
	mce_restart();
	return ret;
}
