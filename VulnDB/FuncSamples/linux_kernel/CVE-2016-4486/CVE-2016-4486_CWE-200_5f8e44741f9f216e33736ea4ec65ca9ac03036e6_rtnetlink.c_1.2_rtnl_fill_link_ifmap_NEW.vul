static int rtnl_fill_link_ifmap(struct sk_buff *skb, struct net_device *dev)
{
	struct rtnl_link_ifmap map;

	memset(&map, 0, sizeof(map));
	map.mem_start   = dev->mem_start;
	map.mem_end     = dev->mem_end;
	map.base_addr   = dev->base_addr;
	map.irq         = dev->irq;
	map.dma         = dev->dma;
	map.port        = dev->if_port;

	if (nla_put(skb, IFLA_MAP, sizeof(map), &map))
		return -EMSGSIZE;

	return 0;
}
