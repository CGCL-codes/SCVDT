static int cdrom_ioctl_media_changed(struct cdrom_device_info *cdi,
		unsigned long arg)
{
	struct cdrom_changer_info *info;
	int ret;

	cd_dbg(CD_DO_IOCTL, "entering CDROM_MEDIA_CHANGED\n");

	if (!CDROM_CAN(CDC_MEDIA_CHANGED))
		return -ENOSYS;

	/* cannot select disc or select current disc */
	if (!CDROM_CAN(CDC_SELECT_DISC) || arg == CDSL_CURRENT)
		return media_changed(cdi, 1);

	if (arg >= cdi->capacity)
		return -EINVAL;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	ret = cdrom_read_mech_status(cdi, info);
	if (!ret)
		ret = info->slots[arg].change;
	kfree(info);
	return ret;
}
