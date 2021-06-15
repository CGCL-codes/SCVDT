static int virtnet_probe(struct virtio_device *vdev)
{
	int i, err;
	struct net_device *dev;
	struct virtnet_info *vi;
	u16 max_queue_pairs;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	if (!virtnet_validate_features(vdev))
		return -EINVAL;

	/* Find if host supports multiqueue virtio_net device */
	err = virtio_cread_feature(vdev, VIRTIO_NET_F_MQ,
				   struct virtio_net_config,
				   max_virtqueue_pairs, &max_queue_pairs);

	/* We need at least 2 queue's */
	if (err || max_queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
	    max_queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
	    !virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
		max_queue_pairs = 1;

	/* Allocate ourselves a network device with room for our info */
	dev = alloc_etherdev_mq(sizeof(struct virtnet_info), max_queue_pairs);
	if (!dev)
		return -ENOMEM;

	/* Set up network device as normal. */
	dev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE;
	dev->netdev_ops = &virtnet_netdev;
	dev->features = NETIF_F_HIGHDMA;

	dev->ethtool_ops = &virtnet_ethtool_ops;
	SET_NETDEV_DEV(dev, &vdev->dev);

	/* Do we support "hardware" checksums? */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_CSUM)) {
		/* This opens up the world of extra features. */
		dev->hw_features |= NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST;
		if (csum)
			dev->features |= NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST;

		if (virtio_has_feature(vdev, VIRTIO_NET_F_GSO)) {
			dev->hw_features |= NETIF_F_TSO | NETIF_F_UFO
				| NETIF_F_TSO_ECN | NETIF_F_TSO6;
		}
		/* Individual feature bits: what can host handle? */
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO4))
			dev->hw_features |= NETIF_F_TSO;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO6))
			dev->hw_features |= NETIF_F_TSO6;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_ECN))
			dev->hw_features |= NETIF_F_TSO_ECN;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_UFO))
			dev->hw_features |= NETIF_F_UFO;

		dev->features |= NETIF_F_GSO_ROBUST;

		if (gso)
			dev->features |= dev->hw_features & (NETIF_F_ALL_TSO|NETIF_F_UFO);
		/* (!csum && gso) case will be fixed by register_netdev() */
	}
	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_CSUM))
		dev->features |= NETIF_F_RXCSUM;

	dev->vlan_features = dev->features;

	/* Configuration may specify what MAC to use.  Otherwise random. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC))
		virtio_cread_bytes(vdev,
				   offsetof(struct virtio_net_config, mac),
				   dev->dev_addr, dev->addr_len);
	else
		eth_hw_addr_random(dev);

	/* Set up our device-specific information */
	vi = netdev_priv(dev);
	vi->dev = dev;
	vi->vdev = vdev;
	vdev->priv = vi;
	vi->stats = alloc_percpu(struct virtnet_stats);
	err = -ENOMEM;
	if (vi->stats == NULL)
		goto free;

	for_each_possible_cpu(i) {
		struct virtnet_stats *virtnet_stats;
		virtnet_stats = per_cpu_ptr(vi->stats, i);
		u64_stats_init(&virtnet_stats->tx_syncp);
		u64_stats_init(&virtnet_stats->rx_syncp);
	}

	INIT_WORK(&vi->config_work, virtnet_config_changed_work);

	/* If we can receive ANY GSO packets, we must allocate large ones. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_ECN) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_UFO))
		vi->big_packets = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF))
		vi->mergeable_rx_bufs = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF) ||
	    virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		vi->hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		vi->hdr_len = sizeof(struct virtio_net_hdr);

	if (virtio_has_feature(vdev, VIRTIO_F_ANY_LAYOUT) ||
	    virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		vi->any_header_sg = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
		vi->has_cvq = true;

	if (vi->any_header_sg)
		dev->needed_headroom = vi->hdr_len;

	/* Use single tx/rx queue pair as default */
	vi->curr_queue_pairs = 1;
	vi->max_queue_pairs = max_queue_pairs;

	/* Allocate/initialize the rx/tx queues, and invoke find_vqs */
	err = init_vqs(vi);
	if (err)
		goto free_stats;

#ifdef CONFIG_SYSFS
	if (vi->mergeable_rx_bufs)
		dev->sysfs_rx_queue_group = &virtio_net_mrg_rx_group;
#endif
	netif_set_real_num_tx_queues(dev, vi->curr_queue_pairs);
	netif_set_real_num_rx_queues(dev, vi->curr_queue_pairs);

	err = register_netdev(dev);
	if (err) {
		pr_debug("virtio_net: registering device failed\n");
		goto free_vqs;
	}

	virtio_device_ready(vdev);

	/* Last of all, set up some receive buffers. */
	for (i = 0; i < vi->curr_queue_pairs; i++) {
		try_fill_recv(vi, &vi->rq[i], GFP_KERNEL);

		/* If we didn't even get one input buffer, we're useless. */
		if (vi->rq[i].vq->num_free ==
		    virtqueue_get_vring_size(vi->rq[i].vq)) {
			free_unused_bufs(vi);
			err = -ENOMEM;
			goto free_recv_bufs;
		}
	}

	vi->nb.notifier_call = &virtnet_cpu_callback;
	err = register_hotcpu_notifier(&vi->nb);
	if (err) {
		pr_debug("virtio_net: registering cpu notifier failed\n");
		goto free_recv_bufs;
	}

	/* Assume link up if device can't report link status,
	   otherwise get link status from config. */
	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_STATUS)) {
		netif_carrier_off(dev);
		schedule_work(&vi->config_work);
	} else {
		vi->status = VIRTIO_NET_S_LINK_UP;
		netif_carrier_on(dev);
	}

	pr_debug("virtnet: registered device %s with %d RX and TX vq's\n",
		 dev->name, max_queue_pairs);

	return 0;

free_recv_bufs:
	vi->vdev->config->reset(vdev);

	free_receive_bufs(vi);
	unregister_netdev(dev);
free_vqs:
	cancel_delayed_work_sync(&vi->refill);
	free_receive_page_frags(vi);
	virtnet_del_vqs(vi);
free_stats:
	free_percpu(vi->stats);
free:
	free_netdev(dev);
	return err;
}
