__be32 ipv6_select_ident(struct net *net,
			 const struct in6_addr *daddr,
			 const struct in6_addr *saddr)
{
	static u32 ip6_idents_hashrnd __read_mostly;
	u32 id;

	net_get_random_once(&ip6_idents_hashrnd, sizeof(ip6_idents_hashrnd));

	id = __ipv6_select_ident(net, ip6_idents_hashrnd, daddr, saddr);
	return htonl(id);
}
