struct btrfs_device *btrfs_find_device(struct btrfs_fs_devices *fs_devices,
				       u64 devid, u8 *uuid, u8 *fsid,
				       bool seed)
{
	struct btrfs_device *device;

	while (fs_devices) {
		if (!fsid ||
		    !memcmp(fs_devices->metadata_uuid, fsid, BTRFS_FSID_SIZE)) {
			list_for_each_entry(device, &fs_devices->devices,
					    dev_list) {
				if (device->devid == devid &&
				    (!uuid || memcmp(device->uuid, uuid,
						     BTRFS_UUID_SIZE) == 0))
					return device;
			}
		}
		if (seed)
			fs_devices = fs_devices->seed;
		else
			return NULL;
	}
	return NULL;
}
