static struct net_bridge_mdb_entry *br_mdb_ip4_get(
	struct net_bridge_mdb_htable *mdb, __be32 dst)
{
	struct br_ip br_dst;

	br_dst.u.ip4 = dst;
	br_dst.proto = htons(ETH_P_IP);

	return br_mdb_ip_get(mdb, &br_dst);
}
