void br_mdb_notify(struct net_device *dev, struct net_bridge_port *port,
		   struct br_ip *group, int type)
{
	struct br_mdb_entry entry;

	memset(&entry, 0, sizeof(entry));
	entry.ifindex = port->dev->ifindex;
	entry.addr.proto = group->proto;
	entry.addr.u.ip4 = group->u.ip4;
#if IS_ENABLED(CONFIG_IPV6)
	entry.addr.u.ip6 = group->u.ip6;
#endif
	__br_mdb_notify(dev, &entry, type);
}
