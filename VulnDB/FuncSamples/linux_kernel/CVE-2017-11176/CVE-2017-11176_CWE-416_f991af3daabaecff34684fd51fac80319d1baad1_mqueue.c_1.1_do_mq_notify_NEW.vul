static int do_mq_notify(mqd_t mqdes, const struct sigevent *notification)
{
	int ret;
	struct fd f;
	struct sock *sock;
	struct inode *inode;
	struct mqueue_inode_info *info;
	struct sk_buff *nc;

	audit_mq_notify(mqdes, notification);

	nc = NULL;
	sock = NULL;
	if (notification != NULL) {
		if (unlikely(notification->sigev_notify != SIGEV_NONE &&
			     notification->sigev_notify != SIGEV_SIGNAL &&
			     notification->sigev_notify != SIGEV_THREAD))
			return -EINVAL;
		if (notification->sigev_notify == SIGEV_SIGNAL &&
			!valid_signal(notification->sigev_signo)) {
			return -EINVAL;
		}
		if (notification->sigev_notify == SIGEV_THREAD) {
			long timeo;

			/* create the notify skb */
			nc = alloc_skb(NOTIFY_COOKIE_LEN, GFP_KERNEL);
			if (!nc) {
				ret = -ENOMEM;
				goto out;
			}
			if (copy_from_user(nc->data,
					notification->sigev_value.sival_ptr,
					NOTIFY_COOKIE_LEN)) {
				ret = -EFAULT;
				goto out;
			}

			/* TODO: add a header? */
			skb_put(nc, NOTIFY_COOKIE_LEN);
			/* and attach it to the socket */
retry:
			f = fdget(notification->sigev_signo);
			if (!f.file) {
				ret = -EBADF;
				goto out;
			}
			sock = netlink_getsockbyfilp(f.file);
			fdput(f);
			if (IS_ERR(sock)) {
				ret = PTR_ERR(sock);
				sock = NULL;
				goto out;
			}

			timeo = MAX_SCHEDULE_TIMEOUT;
			ret = netlink_attachskb(sock, nc, &timeo, NULL);
			if (ret == 1) {
				sock = NULL;
				goto retry;
			}
			if (ret) {
				sock = NULL;
				nc = NULL;
				goto out;
			}
		}
	}

	f = fdget(mqdes);
	if (!f.file) {
		ret = -EBADF;
		goto out;
	}

	inode = file_inode(f.file);
	if (unlikely(f.file->f_op != &mqueue_file_operations)) {
		ret = -EBADF;
		goto out_fput;
	}
	info = MQUEUE_I(inode);

	ret = 0;
	spin_lock(&info->lock);
	if (notification == NULL) {
		if (info->notify_owner == task_tgid(current)) {
			remove_notification(info);
			inode->i_atime = inode->i_ctime = current_time(inode);
		}
	} else if (info->notify_owner != NULL) {
		ret = -EBUSY;
	} else {
		switch (notification->sigev_notify) {
		case SIGEV_NONE:
			info->notify.sigev_notify = SIGEV_NONE;
			break;
		case SIGEV_THREAD:
			info->notify_sock = sock;
			info->notify_cookie = nc;
			sock = NULL;
			nc = NULL;
			info->notify.sigev_notify = SIGEV_THREAD;
			break;
		case SIGEV_SIGNAL:
			info->notify.sigev_signo = notification->sigev_signo;
			info->notify.sigev_value = notification->sigev_value;
			info->notify.sigev_notify = SIGEV_SIGNAL;
			break;
		}

		info->notify_owner = get_pid(task_tgid(current));
		info->notify_user_ns = get_user_ns(current_user_ns());
		inode->i_atime = inode->i_ctime = current_time(inode);
	}
	spin_unlock(&info->lock);
out_fput:
	fdput(f);
out:
	if (sock)
		netlink_detachskb(sock, nc);
	else if (nc)
		dev_kfree_skb(nc);

	return ret;
}
