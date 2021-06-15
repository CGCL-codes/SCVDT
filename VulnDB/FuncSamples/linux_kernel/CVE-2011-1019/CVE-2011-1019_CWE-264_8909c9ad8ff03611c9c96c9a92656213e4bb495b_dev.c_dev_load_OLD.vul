void dev_load(struct net *net, const char *name)
{
	struct net_device *dev;

	rcu_read_lock();
	dev = dev_get_by_name_rcu(net, name);
	rcu_read_unlock();

	if (!dev && capable(CAP_NET_ADMIN))
		request_module("%s", name);
}
