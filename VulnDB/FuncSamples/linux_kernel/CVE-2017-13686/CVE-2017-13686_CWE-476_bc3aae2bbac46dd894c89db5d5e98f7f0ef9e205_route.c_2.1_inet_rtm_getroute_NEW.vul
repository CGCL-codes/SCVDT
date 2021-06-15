static int inet_rtm_getroute(struct sk_buff *in_skb, struct nlmsghdr *nlh,
			     struct netlink_ext_ack *extack)
{
	struct net *net = sock_net(in_skb->sk);
	struct rtmsg *rtm;
	struct nlattr *tb[RTA_MAX+1];
	struct fib_result res = {};
	struct rtable *rt = NULL;
	struct flowi4 fl4;
	__be32 dst = 0;
	__be32 src = 0;
	u32 iif;
	int err;
	int mark;
	struct sk_buff *skb;
	u32 table_id = RT_TABLE_MAIN;
	kuid_t uid;

	err = nlmsg_parse(nlh, sizeof(*rtm), tb, RTA_MAX, rtm_ipv4_policy,
			  extack);
	if (err < 0)
		goto errout;

	rtm = nlmsg_data(nlh);

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		err = -ENOBUFS;
		goto errout;
	}

	/* Reserve room for dummy headers, this skb can pass
	   through good chunk of routing engine.
	 */
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	src = tb[RTA_SRC] ? nla_get_in_addr(tb[RTA_SRC]) : 0;
	dst = tb[RTA_DST] ? nla_get_in_addr(tb[RTA_DST]) : 0;
	iif = tb[RTA_IIF] ? nla_get_u32(tb[RTA_IIF]) : 0;
	mark = tb[RTA_MARK] ? nla_get_u32(tb[RTA_MARK]) : 0;
	if (tb[RTA_UID])
		uid = make_kuid(current_user_ns(), nla_get_u32(tb[RTA_UID]));
	else
		uid = (iif ? INVALID_UID : current_uid());

	/* Bugfix: need to give ip_route_input enough of an IP header to
	 * not gag.
	 */
	ip_hdr(skb)->protocol = IPPROTO_UDP;
	ip_hdr(skb)->saddr = src;
	ip_hdr(skb)->daddr = dst;

	skb_reserve(skb, MAX_HEADER + sizeof(struct iphdr));

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = dst;
	fl4.saddr = src;
	fl4.flowi4_tos = rtm->rtm_tos;
	fl4.flowi4_oif = tb[RTA_OIF] ? nla_get_u32(tb[RTA_OIF]) : 0;
	fl4.flowi4_mark = mark;
	fl4.flowi4_uid = uid;

	rcu_read_lock();

	if (iif) {
		struct net_device *dev;

		dev = dev_get_by_index_rcu(net, iif);
		if (!dev) {
			err = -ENODEV;
			goto errout_free;
		}

		skb->protocol	= htons(ETH_P_IP);
		skb->dev	= dev;
		skb->mark	= mark;
		err = ip_route_input_rcu(skb, dst, src, rtm->rtm_tos,
					 dev, &res);

		rt = skb_rtable(skb);
		if (err == 0 && rt->dst.error)
			err = -rt->dst.error;
	} else {
		rt = ip_route_output_key_hash_rcu(net, &fl4, &res, skb);
		err = 0;
		if (IS_ERR(rt))
			err = PTR_ERR(rt);
		else
			skb_dst_set(skb, &rt->dst);
	}

	if (err)
		goto errout_free;

	if (rtm->rtm_flags & RTM_F_NOTIFY)
		rt->rt_flags |= RTCF_NOTIFY;

	if (rtm->rtm_flags & RTM_F_LOOKUP_TABLE)
		table_id = rt->rt_table_id;

	if (rtm->rtm_flags & RTM_F_FIB_MATCH) {
		if (!res.fi) {
			err = fib_props[res.type].error;
			if (!err)
				err = -EHOSTUNREACH;
			goto errout_free;
		}
		err = fib_dump_info(skb, NETLINK_CB(in_skb).portid,
				    nlh->nlmsg_seq, RTM_NEWROUTE, table_id,
				    rt->rt_type, res.prefix, res.prefixlen,
				    fl4.flowi4_tos, res.fi, 0);
	} else {
		err = rt_fill_info(net, dst, src, table_id, &fl4, skb,
				   NETLINK_CB(in_skb).portid, nlh->nlmsg_seq);
	}
	if (err < 0)
		goto errout_free;

	rcu_read_unlock();

	err = rtnl_unicast(skb, net, NETLINK_CB(in_skb).portid);
errout:
	return err;

errout_free:
	rcu_read_unlock();
	kfree_skb(skb);
	goto errout;
}
