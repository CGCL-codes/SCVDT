struct dst_entry *fib6_rule_lookup(struct net *net, struct flowi6 *fl6,
				   const struct sk_buff *skb,
				   int flags, pol_lookup_t lookup)
{
	struct rt6_info *rt;

	rt = lookup(net, net->ipv6.fib6_main_tbl, fl6, skb, flags);
	if (rt->dst.error == -EAGAIN) {
		ip6_rt_put_flags(rt, flags);
		rt = net->ipv6.ip6_null_entry;
		if (!(flags | RT6_LOOKUP_F_DST_NOREF))
			dst_hold(&rt->dst);
	}

	return &rt->dst;
}
