static int cdrom_ioctl_drive_status(struct cdrom_device_info *cdi,
		unsigned long arg)
{
	cd_dbg(CD_DO_IOCTL, "entering CDROM_DRIVE_STATUS\n");

	if (!(cdi->ops->capability & CDC_DRIVE_STATUS))
		return -ENOSYS;
	if (!CDROM_CAN(CDC_SELECT_DISC) ||
	    (arg == CDSL_CURRENT || arg == CDSL_NONE))
		return cdi->ops->drive_status(cdi, CDSL_CURRENT);
	if (arg >= cdi->capacity)
		return -EINVAL;
	return cdrom_slot_status(cdi, arg);
}
