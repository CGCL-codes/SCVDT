int __init atalk_register_sysctl(void)
{
	atalk_table_header = register_net_sysctl(&init_net, "net/appletalk", atalk_table);
	if (!atalk_table_header)
		return -ENOMEM;
	return 0;
}
