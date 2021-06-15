static int __init sit_init(void)
{
	int err;

	printk(KERN_INFO "IPv6 over IPv4 tunneling driver\n");

	err = register_pernet_device(&sit_net_ops);
	if (err < 0)
		return err;
	err = xfrm4_tunnel_register(&sit_handler, AF_INET6);
	if (err < 0) {
		unregister_pernet_device(&sit_net_ops);
		printk(KERN_INFO "sit init: Can't add protocol\n");
	}
	return err;
}
