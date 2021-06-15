static int addr_doit(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tb[IFA_MAX+1];
	struct net_device *dev;
	struct ifaddrmsg *ifm;
	int err;
	u8 pnaddr;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ASSERT_RTNL();

	err = nlmsg_parse(nlh, sizeof(*ifm), tb, IFA_MAX, ifa_phonet_policy);
	if (err < 0)
		return err;

	ifm = nlmsg_data(nlh);
	if (tb[IFA_LOCAL] == NULL)
		return -EINVAL;
	pnaddr = nla_get_u8(tb[IFA_LOCAL]);
	if (pnaddr & 3)
		/* Phonet addresses only have 6 high-order bits */
		return -EINVAL;

	dev = __dev_get_by_index(net, ifm->ifa_index);
	if (dev == NULL)
		return -ENODEV;

	if (nlh->nlmsg_type == RTM_NEWADDR)
		err = phonet_address_add(dev, pnaddr);
	else
		err = phonet_address_del(dev, pnaddr);
	if (!err)
		phonet_address_notify(nlh->nlmsg_type, dev, pnaddr);
	return err;
}
