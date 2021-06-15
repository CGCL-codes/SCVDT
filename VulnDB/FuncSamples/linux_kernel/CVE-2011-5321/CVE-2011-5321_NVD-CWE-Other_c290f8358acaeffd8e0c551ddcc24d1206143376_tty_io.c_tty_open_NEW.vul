static int tty_open(struct inode *inode, struct file *filp)
{
	struct tty_struct *tty = NULL;
	int noctty, retval;
	struct tty_driver *driver;
	int index;
	dev_t device = inode->i_rdev;
	unsigned saved_flags = filp->f_flags;

	nonseekable_open(inode, filp);

retry_open:
	noctty = filp->f_flags & O_NOCTTY;
	index  = -1;
	retval = 0;

	mutex_lock(&tty_mutex);
	tty_lock();

	if (device == MKDEV(TTYAUX_MAJOR, 0)) {
		tty = get_current_tty();
		if (!tty) {
			tty_unlock();
			mutex_unlock(&tty_mutex);
			return -ENXIO;
		}
		driver = tty_driver_kref_get(tty->driver);
		index = tty->index;
		filp->f_flags |= O_NONBLOCK; /* Don't let /dev/tty block */
		/* noctty = 1; */
		/* FIXME: Should we take a driver reference ? */
		tty_kref_put(tty);
		goto got_driver;
	}
#ifdef CONFIG_VT
	if (device == MKDEV(TTY_MAJOR, 0)) {
		extern struct tty_driver *console_driver;
		driver = tty_driver_kref_get(console_driver);
		index = fg_console;
		noctty = 1;
		goto got_driver;
	}
#endif
	if (device == MKDEV(TTYAUX_MAJOR, 1)) {
		struct tty_driver *console_driver = console_device(&index);
		if (console_driver) {
			driver = tty_driver_kref_get(console_driver);
			if (driver) {
				/* Don't let /dev/console block */
				filp->f_flags |= O_NONBLOCK;
				noctty = 1;
				goto got_driver;
			}
		}
		tty_unlock();
		mutex_unlock(&tty_mutex);
		return -ENODEV;
	}

	driver = get_tty_driver(device, &index);
	if (!driver) {
		tty_unlock();
		mutex_unlock(&tty_mutex);
		return -ENODEV;
	}
got_driver:
	if (!tty) {
		/* check whether we're reopening an existing tty */
		tty = tty_driver_lookup_tty(driver, inode, index);

		if (IS_ERR(tty)) {
			tty_unlock();
			mutex_unlock(&tty_mutex);
			tty_driver_kref_put(driver);
			return PTR_ERR(tty);
		}
	}

	if (tty) {
		retval = tty_reopen(tty);
		if (retval)
			tty = ERR_PTR(retval);
	} else
		tty = tty_init_dev(driver, index, 0);

	mutex_unlock(&tty_mutex);
	tty_driver_kref_put(driver);
	if (IS_ERR(tty)) {
		tty_unlock();
		return PTR_ERR(tty);
	}

	retval = tty_add_file(tty, filp);
	if (retval) {
		tty_unlock();
		tty_release(inode, filp);
		return retval;
	}

	check_tty_count(tty, "tty_open");
	if (tty->driver->type == TTY_DRIVER_TYPE_PTY &&
	    tty->driver->subtype == PTY_TYPE_MASTER)
		noctty = 1;
#ifdef TTY_DEBUG_HANGUP
	printk(KERN_DEBUG "opening %s...", tty->name);
#endif
	if (tty->ops->open)
		retval = tty->ops->open(tty, filp);
	else
		retval = -ENODEV;
	filp->f_flags = saved_flags;

	if (!retval && test_bit(TTY_EXCLUSIVE, &tty->flags) &&
						!capable(CAP_SYS_ADMIN))
		retval = -EBUSY;

	if (retval) {
#ifdef TTY_DEBUG_HANGUP
		printk(KERN_DEBUG "error %d in opening %s...", retval,
		       tty->name);
#endif
		tty_unlock(); /* need to call tty_release without BTM */
		tty_release(inode, filp);
		if (retval != -ERESTARTSYS)
			return retval;

		if (signal_pending(current))
			return retval;

		schedule();
		/*
		 * Need to reset f_op in case a hangup happened.
		 */
		tty_lock();
		if (filp->f_op == &hung_up_tty_fops)
			filp->f_op = &tty_fops;
		tty_unlock();
		goto retry_open;
	}
	tty_unlock();


	mutex_lock(&tty_mutex);
	tty_lock();
	spin_lock_irq(&current->sighand->siglock);
	if (!noctty &&
	    current->signal->leader &&
	    !current->signal->tty &&
	    tty->session == NULL)
		__proc_set_tty(current, tty);
	spin_unlock_irq(&current->sighand->siglock);
	tty_unlock();
	mutex_unlock(&tty_mutex);
	return 0;
}
