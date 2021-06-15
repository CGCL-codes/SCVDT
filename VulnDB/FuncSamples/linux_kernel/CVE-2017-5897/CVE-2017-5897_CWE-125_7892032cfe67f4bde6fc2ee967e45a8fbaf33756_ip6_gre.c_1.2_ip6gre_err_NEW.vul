static void ip6gre_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
		       u8 type, u8 code, int offset, __be32 info)
{
	const struct gre_base_hdr *greh;
	const struct ipv6hdr *ipv6h;
	int grehlen = sizeof(*greh);
	struct ip6_tnl *t;
	int key_off = 0;
	__be16 flags;
	__be32 key;

	if (!pskb_may_pull(skb, offset + grehlen))
		return;
	greh = (const struct gre_base_hdr *)(skb->data + offset);
	flags = greh->flags;
	if (flags & (GRE_VERSION | GRE_ROUTING))
		return;
	if (flags & GRE_CSUM)
		grehlen += 4;
	if (flags & GRE_KEY) {
		key_off = grehlen + offset;
		grehlen += 4;
	}

	if (!pskb_may_pull(skb, offset + grehlen))
		return;
	ipv6h = (const struct ipv6hdr *)skb->data;
	greh = (const struct gre_base_hdr *)(skb->data + offset);
	key = key_off ? *(__be32 *)(skb->data + key_off) : 0;

	t = ip6gre_tunnel_lookup(skb->dev, &ipv6h->daddr, &ipv6h->saddr,
				 key, greh->protocol);
	if (!t)
		return;

	switch (type) {
		__u32 teli;
		struct ipv6_tlv_tnl_enc_lim *tel;
		__u32 mtu;
	case ICMPV6_DEST_UNREACH:
		net_dbg_ratelimited("%s: Path to destination invalid or inactive!\n",
				    t->parms.name);
		break;
	case ICMPV6_TIME_EXCEED:
		if (code == ICMPV6_EXC_HOPLIMIT) {
			net_dbg_ratelimited("%s: Too small hop limit or routing loop in tunnel!\n",
					    t->parms.name);
		}
		break;
	case ICMPV6_PARAMPROB:
		teli = 0;
		if (code == ICMPV6_HDR_FIELD)
			teli = ip6_tnl_parse_tlv_enc_lim(skb, skb->data);

		if (teli && teli == be32_to_cpu(info) - 2) {
			tel = (struct ipv6_tlv_tnl_enc_lim *) &skb->data[teli];
			if (tel->encap_limit == 0) {
				net_dbg_ratelimited("%s: Too small encapsulation limit or routing loop in tunnel!\n",
						    t->parms.name);
			}
		} else {
			net_dbg_ratelimited("%s: Recipient unable to parse tunneled packet!\n",
					    t->parms.name);
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		mtu = be32_to_cpu(info) - offset;
		if (mtu < IPV6_MIN_MTU)
			mtu = IPV6_MIN_MTU;
		t->dev->mtu = mtu;
		break;
	}

	if (time_before(jiffies, t->err_time + IP6TUNNEL_ERR_TIMEO))
		t->err_count++;
	else
		t->err_count = 1;
	t->err_time = jiffies;
}
