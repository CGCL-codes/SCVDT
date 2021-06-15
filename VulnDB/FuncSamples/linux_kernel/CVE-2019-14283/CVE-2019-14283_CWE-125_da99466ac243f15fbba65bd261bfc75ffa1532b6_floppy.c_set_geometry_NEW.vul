static int set_geometry(unsigned int cmd, struct floppy_struct *g,
			       int drive, int type, struct block_device *bdev)
{
	int cnt;

	/* sanity checking for parameters. */
	if ((int)g->sect <= 0 ||
	    (int)g->head <= 0 ||
	    /* check for overflow in max_sector */
	    (int)(g->sect * g->head) <= 0 ||
	    /* check for zero in F_SECT_PER_TRACK */
	    (unsigned char)((g->sect << 2) >> FD_SIZECODE(g)) == 0 ||
	    g->track <= 0 || g->track > UDP->tracks >> STRETCH(g) ||
	    /* check if reserved bits are set */
	    (g->stretch & ~(FD_STRETCH | FD_SWAPSIDES | FD_SECTBASEMASK)) != 0)
		return -EINVAL;
	if (type) {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		mutex_lock(&open_lock);
		if (lock_fdc(drive)) {
			mutex_unlock(&open_lock);
			return -EINTR;
		}
		floppy_type[type] = *g;
		floppy_type[type].name = "user format";
		for (cnt = type << 2; cnt < (type << 2) + 4; cnt++)
			floppy_sizes[cnt] = floppy_sizes[cnt + 0x80] =
			    floppy_type[type].size + 1;
		process_fd_request();
		for (cnt = 0; cnt < N_DRIVE; cnt++) {
			struct block_device *bdev = opened_bdev[cnt];
			if (!bdev || ITYPE(drive_state[cnt].fd_device) != type)
				continue;
			__invalidate_device(bdev, true);
		}
		mutex_unlock(&open_lock);
	} else {
		int oldStretch;

		if (lock_fdc(drive))
			return -EINTR;
		if (cmd != FDDEFPRM) {
			/* notice a disk change immediately, else
			 * we lose our settings immediately*/
			if (poll_drive(true, FD_RAW_NEED_DISK) == -EINTR)
				return -EINTR;
		}
		oldStretch = g->stretch;
		user_params[drive] = *g;
		if (buffer_drive == drive)
			SUPBOUND(buffer_max, user_params[drive].sect);
		current_type[drive] = &user_params[drive];
		floppy_sizes[drive] = user_params[drive].size;
		if (cmd == FDDEFPRM)
			DRS->keep_data = -1;
		else
			DRS->keep_data = 1;
		/* invalidation. Invalidate only when needed, i.e.
		 * when there are already sectors in the buffer cache
		 * whose number will change. This is useful, because
		 * mtools often changes the geometry of the disk after
		 * looking at the boot block */
		if (DRS->maxblock > user_params[drive].sect ||
		    DRS->maxtrack ||
		    ((user_params[drive].sect ^ oldStretch) &
		     (FD_SWAPSIDES | FD_SECTBASEMASK)))
			invalidate_drive(bdev);
		else
			process_fd_request();
	}
	return 0;
}
