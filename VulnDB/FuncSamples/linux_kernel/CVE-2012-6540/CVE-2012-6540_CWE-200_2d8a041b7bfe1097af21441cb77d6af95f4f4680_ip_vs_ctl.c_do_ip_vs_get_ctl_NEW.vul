static int
do_ip_vs_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	unsigned char arg[128];
	int ret = 0;
	unsigned int copylen;
	struct net *net = sock_net(sk);
	struct netns_ipvs *ipvs = net_ipvs(net);

	BUG_ON(!net);
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (cmd < IP_VS_BASE_CTL || cmd > IP_VS_SO_GET_MAX)
		return -EINVAL;

	if (*len < get_arglen[GET_CMDID(cmd)]) {
		pr_err("get_ctl: len %u < %u\n",
		       *len, get_arglen[GET_CMDID(cmd)]);
		return -EINVAL;
	}

	copylen = get_arglen[GET_CMDID(cmd)];
	if (copylen > 128)
		return -EINVAL;

	if (copy_from_user(arg, user, copylen) != 0)
		return -EFAULT;
	/*
	 * Handle daemons first since it has its own locking
	 */
	if (cmd == IP_VS_SO_GET_DAEMON) {
		struct ip_vs_daemon_user d[2];

		memset(&d, 0, sizeof(d));
		if (mutex_lock_interruptible(&ipvs->sync_mutex))
			return -ERESTARTSYS;

		if (ipvs->sync_state & IP_VS_STATE_MASTER) {
			d[0].state = IP_VS_STATE_MASTER;
			strlcpy(d[0].mcast_ifn, ipvs->master_mcast_ifn,
				sizeof(d[0].mcast_ifn));
			d[0].syncid = ipvs->master_syncid;
		}
		if (ipvs->sync_state & IP_VS_STATE_BACKUP) {
			d[1].state = IP_VS_STATE_BACKUP;
			strlcpy(d[1].mcast_ifn, ipvs->backup_mcast_ifn,
				sizeof(d[1].mcast_ifn));
			d[1].syncid = ipvs->backup_syncid;
		}
		if (copy_to_user(user, &d, sizeof(d)) != 0)
			ret = -EFAULT;
		mutex_unlock(&ipvs->sync_mutex);
		return ret;
	}

	if (mutex_lock_interruptible(&__ip_vs_mutex))
		return -ERESTARTSYS;

	switch (cmd) {
	case IP_VS_SO_GET_VERSION:
	{
		char buf[64];

		sprintf(buf, "IP Virtual Server version %d.%d.%d (size=%d)",
			NVERSION(IP_VS_VERSION_CODE), ip_vs_conn_tab_size);
		if (copy_to_user(user, buf, strlen(buf)+1) != 0) {
			ret = -EFAULT;
			goto out;
		}
		*len = strlen(buf)+1;
	}
	break;

	case IP_VS_SO_GET_INFO:
	{
		struct ip_vs_getinfo info;
		info.version = IP_VS_VERSION_CODE;
		info.size = ip_vs_conn_tab_size;
		info.num_services = ipvs->num_services;
		if (copy_to_user(user, &info, sizeof(info)) != 0)
			ret = -EFAULT;
	}
	break;

	case IP_VS_SO_GET_SERVICES:
	{
		struct ip_vs_get_services *get;
		int size;

		get = (struct ip_vs_get_services *)arg;
		size = sizeof(*get) +
			sizeof(struct ip_vs_service_entry) * get->num_services;
		if (*len != size) {
			pr_err("length: %u != %u\n", *len, size);
			ret = -EINVAL;
			goto out;
		}
		ret = __ip_vs_get_service_entries(net, get, user);
	}
	break;

	case IP_VS_SO_GET_SERVICE:
	{
		struct ip_vs_service_entry *entry;
		struct ip_vs_service *svc;
		union nf_inet_addr addr;

		entry = (struct ip_vs_service_entry *)arg;
		addr.ip = entry->addr;
		if (entry->fwmark)
			svc = __ip_vs_svc_fwm_find(net, AF_INET, entry->fwmark);
		else
			svc = __ip_vs_service_find(net, AF_INET,
						   entry->protocol, &addr,
						   entry->port);
		if (svc) {
			ip_vs_copy_service(entry, svc);
			if (copy_to_user(user, entry, sizeof(*entry)) != 0)
				ret = -EFAULT;
		} else
			ret = -ESRCH;
	}
	break;

	case IP_VS_SO_GET_DESTS:
	{
		struct ip_vs_get_dests *get;
		int size;

		get = (struct ip_vs_get_dests *)arg;
		size = sizeof(*get) +
			sizeof(struct ip_vs_dest_entry) * get->num_dests;
		if (*len != size) {
			pr_err("length: %u != %u\n", *len, size);
			ret = -EINVAL;
			goto out;
		}
		ret = __ip_vs_get_dest_entries(net, get, user);
	}
	break;

	case IP_VS_SO_GET_TIMEOUT:
	{
		struct ip_vs_timeout_user t;

		memset(&t, 0, sizeof(t));
		__ip_vs_get_timeouts(net, &t);
		if (copy_to_user(user, &t, sizeof(t)) != 0)
			ret = -EFAULT;
	}
	break;

	default:
		ret = -EINVAL;
	}

out:
	mutex_unlock(&__ip_vs_mutex);
	return ret;
}
