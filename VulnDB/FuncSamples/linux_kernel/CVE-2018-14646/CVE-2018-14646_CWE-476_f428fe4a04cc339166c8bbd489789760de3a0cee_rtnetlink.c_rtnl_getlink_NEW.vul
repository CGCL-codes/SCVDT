static int rtnl_getlink(struct sk_buff *skb, struct nlmsghdr *nlh,
			struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(skb->sk);
	struct net *tgt_net = net;
	struct ifinfomsg *ifm;
	char ifname[IFNAMSIZ];
	struct nlattr *tb[IFLA_MAX+1];
	struct net_device *dev = NULL;
	struct sk_buff *nskb;
	int netnsid = -1;
	int err;
	u32 ext_filter_mask = 0;

	err = nlmsg_parse(nlh, sizeof(*ifm), tb, IFLA_MAX, ifla_policy, extack);
	if (err < 0)
		return err;

	if (tb[IFLA_IF_NETNSID]) {
		netnsid = nla_get_s32(tb[IFLA_IF_NETNSID]);
		tgt_net = get_target_net(NETLINK_CB(skb).sk, netnsid);
		if (IS_ERR(tgt_net))
			return PTR_ERR(tgt_net);
	}

	if (tb[IFLA_IFNAME])
		nla_strlcpy(ifname, tb[IFLA_IFNAME], IFNAMSIZ);

	if (tb[IFLA_EXT_MASK])
		ext_filter_mask = nla_get_u32(tb[IFLA_EXT_MASK]);

	err = -EINVAL;
	ifm = nlmsg_data(nlh);
	if (ifm->ifi_index > 0)
		dev = __dev_get_by_index(tgt_net, ifm->ifi_index);
	else if (tb[IFLA_IFNAME])
		dev = __dev_get_by_name(tgt_net, ifname);
	else
		goto out;

	err = -ENODEV;
	if (dev == NULL)
		goto out;

	err = -ENOBUFS;
	nskb = nlmsg_new(if_nlmsg_size(dev, ext_filter_mask), GFP_KERNEL);
	if (nskb == NULL)
		goto out;

	err = rtnl_fill_ifinfo(nskb, dev, net,
			       RTM_NEWLINK, NETLINK_CB(skb).portid,
			       nlh->nlmsg_seq, 0, 0, ext_filter_mask,
			       0, NULL, netnsid);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in if_nlmsg_size */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(nskb);
	} else
		err = rtnl_unicast(nskb, net, NETLINK_CB(skb).portid);
out:
	if (netnsid >= 0)
		put_net(tgt_net);

	return err;
}
