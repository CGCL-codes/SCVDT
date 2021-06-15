int __init aarp_proto_init(void)
{
	int rc;

	aarp_dl = register_snap_client(aarp_snap_id, aarp_rcv);
	if (!aarp_dl) {
		printk(KERN_CRIT "Unable to register AARP with SNAP.\n");
		return -ENOMEM;
	}
	timer_setup(&aarp_timer, aarp_expire_timeout, 0);
	aarp_timer.expires  = jiffies + sysctl_aarp_expiry_time;
	add_timer(&aarp_timer);
	rc = register_netdevice_notifier(&aarp_notifier);
	if (rc) {
		del_timer_sync(&aarp_timer);
		unregister_snap_client(aarp_dl);
	}
	return rc;
}
