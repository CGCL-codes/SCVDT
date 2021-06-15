static int parse_status(const char *value)
{
	int ret = 0;
	char *c;

	/* skip a header line */
	c = strchr(value, '\n');
	if (!c)
		return -1;
	c++;

	while (*c != '\0') {
		int port, status, speed, devid;
		int sockfd;
		char lbusid[SYSFS_BUS_ID_SIZE];
		struct usbip_imported_device *idev;
		char hub[3];

		ret = sscanf(c, "%2s  %d %d %d %x %u %31s\n",
				hub, &port, &status, &speed,
				&devid, &sockfd, lbusid);

		if (ret < 5) {
			dbg("sscanf failed: %d", ret);
			BUG();
		}

		dbg("hub %s port %d status %d speed %d devid %x",
				hub, port, status, speed, devid);
		dbg("sockfd %u lbusid %s", sockfd, lbusid);

		/* if a device is connected, look at it */
		idev = &vhci_driver->idev[port];
		memset(idev, 0, sizeof(*idev));

		if (strncmp("hs", hub, 2) == 0)
			idev->hub = HUB_SPEED_HIGH;
		else /* strncmp("ss", hub, 2) == 0 */
			idev->hub = HUB_SPEED_SUPER;

		idev->port	= port;
		idev->status	= status;

		idev->devid	= devid;

		idev->busnum	= (devid >> 16);
		idev->devnum	= (devid & 0x0000ffff);

		if (idev->status != VDEV_ST_NULL
		    && idev->status != VDEV_ST_NOTASSIGNED) {
			idev = imported_device_init(idev, lbusid);
			if (!idev) {
				dbg("imported_device_init failed");
				return -1;
			}
		}

		/* go to the next line */
		c = strchr(c, '\n');
		if (!c)
			break;
		c++;
	}

	dbg("exit");

	return 0;
}
