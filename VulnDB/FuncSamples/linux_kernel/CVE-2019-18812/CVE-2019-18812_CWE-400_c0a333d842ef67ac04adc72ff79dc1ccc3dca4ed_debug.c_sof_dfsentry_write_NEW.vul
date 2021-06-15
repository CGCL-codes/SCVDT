static ssize_t sof_dfsentry_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *ppos)
{
#if IS_ENABLED(CONFIG_SND_SOC_SOF_DEBUG_IPC_FLOOD_TEST)
	struct snd_sof_dfsentry *dfse = file->private_data;
	struct snd_sof_dev *sdev = dfse->sdev;
	unsigned long ipc_duration_ms = 0;
	bool flood_duration_test = false;
	unsigned long ipc_count = 0;
	struct dentry *dentry;
	int err;
#endif
	size_t size;
	char *string;
	int ret;

	string = kzalloc(count, GFP_KERNEL);
	if (!string)
		return -ENOMEM;

	size = simple_write_to_buffer(string, count, ppos, buffer, count);
	ret = size;

#if IS_ENABLED(CONFIG_SND_SOC_SOF_DEBUG_IPC_FLOOD_TEST)
	/*
	 * write op is only supported for ipc_flood_count or
	 * ipc_flood_duration_ms debugfs entries atm.
	 * ipc_flood_count floods the DSP with the number of IPC's specified.
	 * ipc_duration_ms test floods the DSP for the time specified
	 * in the debugfs entry.
	 */
	dentry = file->f_path.dentry;
	if (strcmp(dentry->d_name.name, "ipc_flood_count") &&
	    strcmp(dentry->d_name.name, "ipc_flood_duration_ms")) {
		ret = -EINVAL;
		goto out;
	}

	if (!strcmp(dentry->d_name.name, "ipc_flood_duration_ms"))
		flood_duration_test = true;

	/* test completion criterion */
	if (flood_duration_test)
		ret = kstrtoul(string, 0, &ipc_duration_ms);
	else
		ret = kstrtoul(string, 0, &ipc_count);
	if (ret < 0)
		goto out;

	/* limit max duration/ipc count for flood test */
	if (flood_duration_test) {
		if (!ipc_duration_ms) {
			ret = size;
			goto out;
		}

		/* find the minimum. min() is not used to avoid warnings */
		if (ipc_duration_ms > MAX_IPC_FLOOD_DURATION_MS)
			ipc_duration_ms = MAX_IPC_FLOOD_DURATION_MS;
	} else {
		if (!ipc_count) {
			ret = size;
			goto out;
		}

		/* find the minimum. min() is not used to avoid warnings */
		if (ipc_count > MAX_IPC_FLOOD_COUNT)
			ipc_count = MAX_IPC_FLOOD_COUNT;
	}

	ret = pm_runtime_get_sync(sdev->dev);
	if (ret < 0) {
		dev_err_ratelimited(sdev->dev,
				    "error: debugfs write failed to resume %d\n",
				    ret);
		pm_runtime_put_noidle(sdev->dev);
		goto out;
	}

	/* flood test */
	ret = sof_debug_ipc_flood_test(sdev, dfse, flood_duration_test,
				       ipc_duration_ms, ipc_count);

	pm_runtime_mark_last_busy(sdev->dev);
	err = pm_runtime_put_autosuspend(sdev->dev);
	if (err < 0)
		dev_err_ratelimited(sdev->dev,
				    "error: debugfs write failed to idle %d\n",
				    err);

	/* return size if test is successful */
	if (ret >= 0)
		ret = size;
out:
#endif
	kfree(string);
	return ret;
}
