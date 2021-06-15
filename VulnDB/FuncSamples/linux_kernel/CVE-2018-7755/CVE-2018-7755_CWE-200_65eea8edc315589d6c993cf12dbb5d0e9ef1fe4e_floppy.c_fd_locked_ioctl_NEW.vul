static int fd_locked_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
		    unsigned long param)
{
	int drive = (long)bdev->bd_disk->private_data;
	int type = ITYPE(UDRS->fd_device);
	int i;
	int ret;
	int size;
	union inparam {
		struct floppy_struct g;	/* geometry */
		struct format_descr f;
		struct floppy_max_errors max_errors;
		struct floppy_drive_params dp;
	} inparam;		/* parameters coming from user space */
	const void *outparam;	/* parameters passed back to user space */

	/* convert compatibility eject ioctls into floppy eject ioctl.
	 * We do this in order to provide a means to eject floppy disks before
	 * installing the new fdutils package */
	if (cmd == CDROMEJECT ||	/* CD-ROM eject */
	    cmd == 0x6470) {		/* SunOS floppy eject */
		DPRINT("obsolete eject ioctl\n");
		DPRINT("please use floppycontrol --eject\n");
		cmd = FDEJECT;
	}

	if (!((cmd & 0xff00) == 0x0200))
		return -EINVAL;

	/* convert the old style command into a new style command */
	ret = normalize_ioctl(&cmd, &size);
	if (ret)
		return ret;

	/* permission checks */
	if (((cmd & 0x40) && !(mode & (FMODE_WRITE | FMODE_WRITE_IOCTL))) ||
	    ((cmd & 0x80) && !capable(CAP_SYS_ADMIN)))
		return -EPERM;

	if (WARN_ON(size < 0 || size > sizeof(inparam)))
		return -EINVAL;

	/* copyin */
	memset(&inparam, 0, sizeof(inparam));
	if (_IOC_DIR(cmd) & _IOC_WRITE) {
		ret = fd_copyin((void __user *)param, &inparam, size);
		if (ret)
			return ret;
	}

	switch (cmd) {
	case FDEJECT:
		if (UDRS->fd_ref != 1)
			/* somebody else has this drive open */
			return -EBUSY;
		if (lock_fdc(drive))
			return -EINTR;

		/* do the actual eject. Fails on
		 * non-Sparc architectures */
		ret = fd_eject(UNIT(drive));

		set_bit(FD_DISK_CHANGED_BIT, &UDRS->flags);
		set_bit(FD_VERIFY_BIT, &UDRS->flags);
		process_fd_request();
		return ret;
	case FDCLRPRM:
		if (lock_fdc(drive))
			return -EINTR;
		current_type[drive] = NULL;
		floppy_sizes[drive] = MAX_DISK_SIZE << 1;
		UDRS->keep_data = 0;
		return invalidate_drive(bdev);
	case FDSETPRM:
	case FDDEFPRM:
		return set_geometry(cmd, &inparam.g, drive, type, bdev);
	case FDGETPRM:
		ret = get_floppy_geometry(drive, type,
					  (struct floppy_struct **)&outparam);
		if (ret)
			return ret;
		memcpy(&inparam.g, outparam,
				offsetof(struct floppy_struct, name));
		outparam = &inparam.g;
		break;
	case FDMSGON:
		UDP->flags |= FTD_MSG;
		return 0;
	case FDMSGOFF:
		UDP->flags &= ~FTD_MSG;
		return 0;
	case FDFMTBEG:
		if (lock_fdc(drive))
			return -EINTR;
		if (poll_drive(true, FD_RAW_NEED_DISK) == -EINTR)
			return -EINTR;
		ret = UDRS->flags;
		process_fd_request();
		if (ret & FD_VERIFY)
			return -ENODEV;
		if (!(ret & FD_DISK_WRITABLE))
			return -EROFS;
		return 0;
	case FDFMTTRK:
		if (UDRS->fd_ref != 1)
			return -EBUSY;
		return do_format(drive, &inparam.f);
	case FDFMTEND:
	case FDFLUSH:
		if (lock_fdc(drive))
			return -EINTR;
		return invalidate_drive(bdev);
	case FDSETEMSGTRESH:
		UDP->max_errors.reporting = (unsigned short)(param & 0x0f);
		return 0;
	case FDGETMAXERRS:
		outparam = &UDP->max_errors;
		break;
	case FDSETMAXERRS:
		UDP->max_errors = inparam.max_errors;
		break;
	case FDGETDRVTYP:
		outparam = drive_name(type, drive);
		SUPBOUND(size, strlen((const char *)outparam) + 1);
		break;
	case FDSETDRVPRM:
		*UDP = inparam.dp;
		break;
	case FDGETDRVPRM:
		outparam = UDP;
		break;
	case FDPOLLDRVSTAT:
		if (lock_fdc(drive))
			return -EINTR;
		if (poll_drive(true, FD_RAW_NEED_DISK) == -EINTR)
			return -EINTR;
		process_fd_request();
		/* fall through */
	case FDGETDRVSTAT:
		outparam = UDRS;
		break;
	case FDRESET:
		return user_reset_fdc(drive, (int)param, true);
	case FDGETFDCSTAT:
		outparam = UFDCS;
		break;
	case FDWERRORCLR:
		memset(UDRWE, 0, sizeof(*UDRWE));
		return 0;
	case FDWERRORGET:
		outparam = UDRWE;
		break;
	case FDRAWCMD:
		if (type)
			return -EINVAL;
		if (lock_fdc(drive))
			return -EINTR;
		set_floppy(drive);
		i = raw_cmd_ioctl(cmd, (void __user *)param);
		if (i == -EINTR)
			return -EINTR;
		process_fd_request();
		return i;
	case FDTWADDLE:
		if (lock_fdc(drive))
			return -EINTR;
		twaddle();
		process_fd_request();
		return 0;
	default:
		return -EINVAL;
	}

	if (_IOC_DIR(cmd) & _IOC_READ)
		return fd_copyout((void __user *)param, outparam, size);

	return 0;
}
