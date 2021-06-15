static int tun_set_iff(struct net *net, struct file *file, struct ifreq *ifr)
{
	struct tun_struct *tun;
	struct tun_file *tfile = file->private_data;
	struct net_device *dev;
	int err;

	if (tfile->detached)
		return -EINVAL;

	dev = __dev_get_by_name(net, ifr->ifr_name);
	if (dev) {
		if (ifr->ifr_flags & IFF_TUN_EXCL)
			return -EBUSY;
		if ((ifr->ifr_flags & IFF_TUN) && dev->netdev_ops == &tun_netdev_ops)
			tun = netdev_priv(dev);
		else if ((ifr->ifr_flags & IFF_TAP) && dev->netdev_ops == &tap_netdev_ops)
			tun = netdev_priv(dev);
		else
			return -EINVAL;

		if (!!(ifr->ifr_flags & IFF_MULTI_QUEUE) !=
		    !!(tun->flags & IFF_MULTI_QUEUE))
			return -EINVAL;

		if (tun_not_capable(tun))
			return -EPERM;
		err = security_tun_dev_open(tun->security);
		if (err < 0)
			return err;

		err = tun_attach(tun, file, ifr->ifr_flags & IFF_NOFILTER);
		if (err < 0)
			return err;

		if (tun->flags & IFF_MULTI_QUEUE &&
		    (tun->numqueues + tun->numdisabled > 1)) {
			/* One or more queue has already been attached, no need
			 * to initialize the device again.
			 */
			return 0;
		}
	}
	else {
		char *name;
		unsigned long flags = 0;
		int queues = ifr->ifr_flags & IFF_MULTI_QUEUE ?
			     MAX_TAP_QUEUES : 1;

		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		err = security_tun_dev_create();
		if (err < 0)
			return err;

		/* Set dev type */
		if (ifr->ifr_flags & IFF_TUN) {
			/* TUN device */
			flags |= IFF_TUN;
			name = "tun%d";
		} else if (ifr->ifr_flags & IFF_TAP) {
			/* TAP device */
			flags |= IFF_TAP;
			name = "tap%d";
		} else
			return -EINVAL;

		if (*ifr->ifr_name)
			name = ifr->ifr_name;

		dev = alloc_netdev_mqs(sizeof(struct tun_struct), name,
				       NET_NAME_UNKNOWN, tun_setup, queues,
				       queues);

		if (!dev)
			return -ENOMEM;
		err = dev_get_valid_name(net, dev, name);
		if (err < 0)
			goto err_free_dev;

		dev_net_set(dev, net);
		dev->rtnl_link_ops = &tun_link_ops;
		dev->ifindex = tfile->ifindex;
		dev->sysfs_groups[0] = &tun_attr_group;

		tun = netdev_priv(dev);
		tun->dev = dev;
		tun->flags = flags;
		tun->txflt.count = 0;
		tun->vnet_hdr_sz = sizeof(struct virtio_net_hdr);

		tun->align = NET_SKB_PAD;
		tun->filter_attached = false;
		tun->sndbuf = tfile->socket.sk->sk_sndbuf;
		tun->rx_batched = 0;

		tun->pcpu_stats = netdev_alloc_pcpu_stats(struct tun_pcpu_stats);
		if (!tun->pcpu_stats) {
			err = -ENOMEM;
			goto err_free_dev;
		}

		spin_lock_init(&tun->lock);

		err = security_tun_dev_alloc_security(&tun->security);
		if (err < 0)
			goto err_free_stat;

		tun_net_init(dev);
		tun_flow_init(tun);

		dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST |
				   TUN_USER_FEATURES | NETIF_F_HW_VLAN_CTAG_TX |
				   NETIF_F_HW_VLAN_STAG_TX;
		dev->features = dev->hw_features | NETIF_F_LLTX;
		dev->vlan_features = dev->features &
				     ~(NETIF_F_HW_VLAN_CTAG_TX |
				       NETIF_F_HW_VLAN_STAG_TX);

		INIT_LIST_HEAD(&tun->disabled);
		err = tun_attach(tun, file, false);
		if (err < 0)
			goto err_free_flow;

		err = register_netdevice(tun->dev);
		if (err < 0)
			goto err_detach;
	}

	netif_carrier_on(tun->dev);

	tun_debug(KERN_INFO, tun, "tun_set_iff\n");

	tun->flags = (tun->flags & ~TUN_FEATURES) |
		(ifr->ifr_flags & TUN_FEATURES);

	/* Make sure persistent devices do not get stuck in
	 * xoff state.
	 */
	if (netif_running(tun->dev))
		netif_tx_wake_all_queues(tun->dev);

	strcpy(ifr->ifr_name, tun->dev->name);
	return 0;

err_detach:
	tun_detach_all(dev);
	/* register_netdevice() already called tun_free_netdev() */
	goto err_free_dev;

err_free_flow:
	tun_flow_uninit(tun);
	security_tun_dev_free_security(tun->security);
err_free_stat:
	free_percpu(tun->pcpu_stats);
err_free_dev:
	free_netdev(dev);
	return err;
}
