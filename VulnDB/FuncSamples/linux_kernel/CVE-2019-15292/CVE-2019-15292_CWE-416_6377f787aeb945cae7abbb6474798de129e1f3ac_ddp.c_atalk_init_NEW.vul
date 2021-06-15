static int __init atalk_init(void)
{
	int rc;

	rc = proto_register(&ddp_proto, 0);
	if (rc)
		goto out;

	rc = sock_register(&atalk_family_ops);
	if (rc)
		goto out_proto;

	ddp_dl = register_snap_client(ddp_snap_id, atalk_rcv);
	if (!ddp_dl)
		printk(atalk_err_snap);

	dev_add_pack(&ltalk_packet_type);
	dev_add_pack(&ppptalk_packet_type);

	rc = register_netdevice_notifier(&ddp_notifier);
	if (rc)
		goto out_sock;

	aarp_proto_init();
	rc = atalk_proc_init();
	if (rc)
		goto out_aarp;

	rc = atalk_register_sysctl();
	if (rc)
		goto out_proc;
out:
	return rc;
out_proc:
	atalk_proc_exit();
out_aarp:
	aarp_cleanup_module();
	unregister_netdevice_notifier(&ddp_notifier);
out_sock:
	dev_remove_pack(&ppptalk_packet_type);
	dev_remove_pack(&ltalk_packet_type);
	unregister_snap_client(ddp_dl);
	sock_unregister(PF_APPLETALK);
out_proto:
	proto_unregister(&ddp_proto);
	goto out;
}
