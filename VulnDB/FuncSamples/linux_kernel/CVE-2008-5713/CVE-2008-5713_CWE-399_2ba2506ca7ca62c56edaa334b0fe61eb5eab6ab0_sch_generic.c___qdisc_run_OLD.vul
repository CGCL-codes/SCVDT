void __qdisc_run(struct net_device *dev)
{
	do {
		if (!qdisc_restart(dev))
			break;
	} while (!netif_queue_stopped(dev));

	clear_bit(__LINK_STATE_QDISC_RUNNING, &dev->state);
}
