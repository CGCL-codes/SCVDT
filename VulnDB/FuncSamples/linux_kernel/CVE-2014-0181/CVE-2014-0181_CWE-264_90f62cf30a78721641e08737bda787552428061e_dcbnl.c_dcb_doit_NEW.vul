static int dcb_doit(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct net_device *netdev;
	struct dcbmsg *dcb = nlmsg_data(nlh);
	struct nlattr *tb[DCB_ATTR_MAX + 1];
	u32 portid = skb ? NETLINK_CB(skb).portid : 0;
	int ret = -EINVAL;
	struct sk_buff *reply_skb;
	struct nlmsghdr *reply_nlh = NULL;
	const struct reply_func *fn;

	if ((nlh->nlmsg_type == RTM_SETDCB) && !netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	ret = nlmsg_parse(nlh, sizeof(*dcb), tb, DCB_ATTR_MAX,
			  dcbnl_rtnl_policy);
	if (ret < 0)
		return ret;

	if (dcb->cmd > DCB_CMD_MAX)
		return -EINVAL;

	/* check if a reply function has been defined for the command */
	fn = &reply_funcs[dcb->cmd];
	if (!fn->cb)
		return -EOPNOTSUPP;

	if (!tb[DCB_ATTR_IFNAME])
		return -EINVAL;

	netdev = __dev_get_by_name(net, nla_data(tb[DCB_ATTR_IFNAME]));
	if (!netdev)
		return -ENODEV;

	if (!netdev->dcbnl_ops)
		return -EOPNOTSUPP;

	reply_skb = dcbnl_newmsg(fn->type, dcb->cmd, portid, nlh->nlmsg_seq,
				 nlh->nlmsg_flags, &reply_nlh);
	if (!reply_skb)
		return -ENOBUFS;

	ret = fn->cb(netdev, nlh, nlh->nlmsg_seq, tb, reply_skb);
	if (ret < 0) {
		nlmsg_free(reply_skb);
		goto out;
	}

	nlmsg_end(reply_skb, reply_nlh);

	ret = rtnl_unicast(reply_skb, net, portid);
out:
	return ret;
}
