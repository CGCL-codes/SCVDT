static int register_queue_kobjects(struct net_device *dev)
{
	int error = 0, txq = 0, rxq = 0, real_rx = 0, real_tx = 0;

#ifdef CONFIG_SYSFS
	dev->queues_kset = kset_create_and_add("queues",
					       NULL, &dev->dev.kobj);
	if (!dev->queues_kset)
		return -ENOMEM;
	real_rx = dev->real_num_rx_queues;
#endif
	real_tx = dev->real_num_tx_queues;

	error = net_rx_queue_update_kobjects(dev, 0, real_rx);
	if (error)
		goto error;
	rxq = real_rx;

	error = netdev_queue_update_kobjects(dev, 0, real_tx);
	if (error)
		goto error;
	txq = real_tx;

	return 0;

error:
	netdev_queue_update_kobjects(dev, txq, 0);
	net_rx_queue_update_kobjects(dev, rxq, 0);
#ifdef CONFIG_SYSFS
	kset_unregister(dev->queues_kset);
#endif
	return error;
}
