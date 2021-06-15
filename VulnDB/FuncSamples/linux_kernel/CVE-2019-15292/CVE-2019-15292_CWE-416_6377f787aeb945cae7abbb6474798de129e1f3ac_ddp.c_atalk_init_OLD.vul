static int __init atalk_init(void)
{
	int rc = proto_register(&ddp_proto, 0);

	if (rc != 0)
		goto out;

	(void)sock_register(&atalk_family_ops);
	ddp_dl = register_snap_client(ddp_snap_id, atalk_rcv);
	if (!ddp_dl)
		printk(atalk_err_snap);

	dev_add_pack(&ltalk_packet_type);
	dev_add_pack(&ppptalk_packet_type);

	register_netdevice_notifier(&ddp_notifier);
	aarp_proto_init();
	atalk_proc_init();
	atalk_register_sysctl();
out:
	return rc;
}
