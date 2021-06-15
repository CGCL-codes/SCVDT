static struct net_bridge_mdb_entry *br_mdb_ip6_get(
	struct net_bridge_mdb_htable *mdb, const struct in6_addr *dst)
{
	struct br_ip br_dst;

	ipv6_addr_copy(&br_dst.u.ip6, dst);
	br_dst.proto = htons(ETH_P_IPV6);

	return br_mdb_ip_get(mdb, &br_dst);
}
