static int rtnl_group_changelink(struct net *net, int group,
		struct ifinfomsg *ifm,
		struct nlattr **tb)
{
	struct net_device *dev;
	int err;

	for_each_netdev(net, dev) {
		if (dev->group == group) {
			err = do_setlink(dev, ifm, tb, NULL, 0);
			if (err < 0)
				return err;
		}
	}

	return 0;
}
