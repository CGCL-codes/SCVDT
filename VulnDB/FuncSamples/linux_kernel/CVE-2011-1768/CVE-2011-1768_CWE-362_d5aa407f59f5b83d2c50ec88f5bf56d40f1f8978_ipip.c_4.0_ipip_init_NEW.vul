static int __init ipip_init(void)
{
	int err;

	printk(banner);

	err = register_pernet_device(&ipip_net_ops);
	if (err < 0)
		return err;
	err = xfrm4_tunnel_register(&ipip_handler, AF_INET);
	if (err < 0) {
		unregister_pernet_device(&ipip_net_ops);
		printk(KERN_INFO "ipip init: can't register tunnel\n");
	}
	return err;
}
