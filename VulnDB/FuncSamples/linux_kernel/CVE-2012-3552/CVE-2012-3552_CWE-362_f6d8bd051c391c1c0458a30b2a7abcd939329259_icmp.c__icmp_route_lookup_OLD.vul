static struct rtable *icmp_route_lookup(struct net *net, struct sk_buff *skb_in,
					const struct iphdr *iph,
					__be32 saddr, u8 tos,
					int type, int code,
					struct icmp_bxm *param)
{
	struct flowi4 fl4 = {
		.daddr = (param->replyopts.srr ?
			  param->replyopts.faddr : iph->saddr),
		.saddr = saddr,
		.flowi4_tos = RT_TOS(tos),
		.flowi4_proto = IPPROTO_ICMP,
		.fl4_icmp_type = type,
		.fl4_icmp_code = code,
	};
	struct rtable *rt, *rt2;
	int err;

	security_skb_classify_flow(skb_in, flowi4_to_flowi(&fl4));
	rt = __ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return rt;

	/* No need to clone since we're just using its address. */
	rt2 = rt;

	if (!fl4.saddr)
		fl4.saddr = rt->rt_src;

	rt = (struct rtable *) xfrm_lookup(net, &rt->dst,
					   flowi4_to_flowi(&fl4), NULL, 0);
	if (!IS_ERR(rt)) {
		if (rt != rt2)
			return rt;
	} else if (PTR_ERR(rt) == -EPERM) {
		rt = NULL;
	} else
		return rt;

	err = xfrm_decode_session_reverse(skb_in, flowi4_to_flowi(&fl4), AF_INET);
	if (err)
		goto relookup_failed;

	if (inet_addr_type(net, fl4.saddr) == RTN_LOCAL) {
		rt2 = __ip_route_output_key(net, &fl4);
		if (IS_ERR(rt2))
			err = PTR_ERR(rt2);
	} else {
		struct flowi4 fl4_2 = {};
		unsigned long orefdst;

		fl4_2.daddr = fl4.saddr;
		rt2 = ip_route_output_key(net, &fl4_2);
		if (IS_ERR(rt2)) {
			err = PTR_ERR(rt2);
			goto relookup_failed;
		}
		/* Ugh! */
		orefdst = skb_in->_skb_refdst; /* save old refdst */
		err = ip_route_input(skb_in, fl4.daddr, fl4.saddr,
				     RT_TOS(tos), rt2->dst.dev);

		dst_release(&rt2->dst);
		rt2 = skb_rtable(skb_in);
		skb_in->_skb_refdst = orefdst; /* restore old refdst */
	}

	if (err)
		goto relookup_failed;

	rt2 = (struct rtable *) xfrm_lookup(net, &rt2->dst,
					    flowi4_to_flowi(&fl4), NULL,
					    XFRM_LOOKUP_ICMP);
	if (!IS_ERR(rt2)) {
		dst_release(&rt->dst);
		rt = rt2;
	} else if (PTR_ERR(rt2) == -EPERM) {
		if (rt)
			dst_release(&rt->dst);
		return rt2;
	} else {
		err = PTR_ERR(rt2);
		goto relookup_failed;
	}
	return rt;

relookup_failed:
	if (rt)
		return rt;
	return ERR_PTR(err);
}
