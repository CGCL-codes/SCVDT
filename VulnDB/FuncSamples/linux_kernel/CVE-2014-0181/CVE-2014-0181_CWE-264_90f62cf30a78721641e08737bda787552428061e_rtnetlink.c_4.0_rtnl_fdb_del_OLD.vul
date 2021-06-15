static int rtnl_fdb_del(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct ndmsg *ndm;
	struct nlattr *tb[NDA_MAX+1];
	struct net_device *dev;
	int err = -EINVAL;
	__u8 *addr;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	err = nlmsg_parse(nlh, sizeof(*ndm), tb, NDA_MAX, NULL);
	if (err < 0)
		return err;

	ndm = nlmsg_data(nlh);
	if (ndm->ndm_ifindex == 0) {
		pr_info("PF_BRIDGE: RTM_DELNEIGH with invalid ifindex\n");
		return -EINVAL;
	}

	dev = __dev_get_by_index(net, ndm->ndm_ifindex);
	if (dev == NULL) {
		pr_info("PF_BRIDGE: RTM_DELNEIGH with unknown ifindex\n");
		return -ENODEV;
	}

	if (!tb[NDA_LLADDR] || nla_len(tb[NDA_LLADDR]) != ETH_ALEN) {
		pr_info("PF_BRIDGE: RTM_DELNEIGH with invalid address\n");
		return -EINVAL;
	}

	addr = nla_data(tb[NDA_LLADDR]);

	err = -EOPNOTSUPP;

	/* Support fdb on master device the net/bridge default case */
	if ((!ndm->ndm_flags || ndm->ndm_flags & NTF_MASTER) &&
	    (dev->priv_flags & IFF_BRIDGE_PORT)) {
		struct net_device *br_dev = netdev_master_upper_dev_get(dev);
		const struct net_device_ops *ops = br_dev->netdev_ops;

		if (ops->ndo_fdb_del)
			err = ops->ndo_fdb_del(ndm, tb, dev, addr);

		if (err)
			goto out;
		else
			ndm->ndm_flags &= ~NTF_MASTER;
	}

	/* Embedded bridge, macvlan, and any other device support */
	if (ndm->ndm_flags & NTF_SELF) {
		if (dev->netdev_ops->ndo_fdb_del)
			err = dev->netdev_ops->ndo_fdb_del(ndm, tb, dev, addr);
		else
			err = ndo_dflt_fdb_del(ndm, tb, dev, addr);

		if (!err) {
			rtnl_fdb_notify(dev, addr, RTM_DELNEIGH);
			ndm->ndm_flags &= ~NTF_SELF;
		}
	}
out:
	return err;
}
