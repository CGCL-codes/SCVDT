static int route_doit(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tb[RTA_MAX+1];
	struct net_device *dev;
	struct rtmsg *rtm;
	int err;
	u8 dst;

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	if (!netlink_capable(skb, CAP_SYS_ADMIN))
		return -EPERM;

	ASSERT_RTNL();

	err = nlmsg_parse(nlh, sizeof(*rtm), tb, RTA_MAX, rtm_phonet_policy);
	if (err < 0)
		return err;

	rtm = nlmsg_data(nlh);
	if (rtm->rtm_table != RT_TABLE_MAIN || rtm->rtm_type != RTN_UNICAST)
		return -EINVAL;
	if (tb[RTA_DST] == NULL || tb[RTA_OIF] == NULL)
		return -EINVAL;
	dst = nla_get_u8(tb[RTA_DST]);
	if (dst & 3) /* Phonet addresses only have 6 high-order bits */
		return -EINVAL;

	dev = __dev_get_by_index(net, nla_get_u32(tb[RTA_OIF]));
	if (dev == NULL)
		return -ENODEV;

	if (nlh->nlmsg_type == RTM_NEWROUTE)
		err = phonet_route_add(dev, dst);
	else
		err = phonet_route_del(dev, dst);
	if (!err)
		rtm_phonet_notify(nlh->nlmsg_type, dev, dst);
	return err;
}
