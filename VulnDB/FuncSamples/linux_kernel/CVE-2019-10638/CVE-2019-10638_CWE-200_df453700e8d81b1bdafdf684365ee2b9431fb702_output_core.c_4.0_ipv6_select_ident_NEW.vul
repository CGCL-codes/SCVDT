__be32 ipv6_select_ident(struct net *net,
			 const struct in6_addr *daddr,
			 const struct in6_addr *saddr)
{
	u32 id;

	id = __ipv6_select_ident(net, daddr, saddr);
	return htonl(id);
}
