static ssize_t match_busid_show(struct device_driver *drv, char *buf)
{
	int i;
	char *out = buf;

	spin_lock(&busid_table_lock);
	for (i = 0; i < MAX_BUSID; i++) {
		spin_lock(&busid_table[i].busid_lock);
		if (busid_table[i].name[0])
			out += sprintf(out, "%s ", busid_table[i].name);
		spin_unlock(&busid_table[i].busid_lock);
	}
	spin_unlock(&busid_table_lock);
	out += sprintf(out, "\n");

	return out - buf;
}
