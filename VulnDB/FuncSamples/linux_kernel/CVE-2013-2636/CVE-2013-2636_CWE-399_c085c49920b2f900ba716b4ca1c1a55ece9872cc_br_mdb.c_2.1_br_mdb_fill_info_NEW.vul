static int br_mdb_fill_info(struct sk_buff *skb, struct netlink_callback *cb,
			    struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_mdb_htable *mdb;
	struct nlattr *nest, *nest2;
	int i, err = 0;
	int idx = 0, s_idx = cb->args[1];

	if (br->multicast_disabled)
		return 0;

	mdb = rcu_dereference(br->mdb);
	if (!mdb)
		return 0;

	nest = nla_nest_start(skb, MDBA_MDB);
	if (nest == NULL)
		return -EMSGSIZE;

	for (i = 0; i < mdb->max; i++) {
		struct net_bridge_mdb_entry *mp;
		struct net_bridge_port_group *p, **pp;
		struct net_bridge_port *port;

		hlist_for_each_entry_rcu(mp, &mdb->mhash[i], hlist[mdb->ver]) {
			if (idx < s_idx)
				goto skip;

			nest2 = nla_nest_start(skb, MDBA_MDB_ENTRY);
			if (nest2 == NULL) {
				err = -EMSGSIZE;
				goto out;
			}

			for (pp = &mp->ports;
			     (p = rcu_dereference(*pp)) != NULL;
			      pp = &p->next) {
				port = p->port;
				if (port) {
					struct br_mdb_entry e;
					memset(&e, 0, sizeof(e));
					e.ifindex = port->dev->ifindex;
					e.state = p->state;
					if (p->addr.proto == htons(ETH_P_IP))
						e.addr.u.ip4 = p->addr.u.ip4;
#if IS_ENABLED(CONFIG_IPV6)
					if (p->addr.proto == htons(ETH_P_IPV6))
						e.addr.u.ip6 = p->addr.u.ip6;
#endif
					e.addr.proto = p->addr.proto;
					if (nla_put(skb, MDBA_MDB_ENTRY_INFO, sizeof(e), &e)) {
						nla_nest_cancel(skb, nest2);
						err = -EMSGSIZE;
						goto out;
					}
				}
			}
			nla_nest_end(skb, nest2);
		skip:
			idx++;
		}
	}

out:
	cb->args[1] = idx;
	nla_nest_end(skb, nest);
	return err;
}
