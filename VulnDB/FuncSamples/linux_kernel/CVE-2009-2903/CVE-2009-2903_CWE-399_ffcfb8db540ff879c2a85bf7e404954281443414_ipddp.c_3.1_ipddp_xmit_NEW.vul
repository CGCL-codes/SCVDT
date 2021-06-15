static netdev_tx_t ipddp_xmit(struct sk_buff *skb, struct net_device *dev)
{
	__be32 paddr = skb_rtable(skb)->rt_gateway;
        struct ddpehdr *ddp;
        struct ipddp_route *rt;
        struct atalk_addr *our_addr;

	spin_lock(&ipddp_route_lock);

	/*
         * Find appropriate route to use, based only on IP number.
         */
        for(rt = ipddp_route_list; rt != NULL; rt = rt->next)
        {
                if(rt->ip == paddr)
                        break;
        }
        if(rt == NULL) {
		spin_unlock(&ipddp_route_lock);
                return NETDEV_TX_OK;
	}

        our_addr = atalk_find_dev_addr(rt->dev);

	if(ipddp_mode == IPDDP_DECAP)
		/* 
		 * Pull off the excess room that should not be there.
		 * This is due to a hard-header problem. This is the
		 * quick fix for now though, till it breaks.
		 */
		skb_pull(skb, 35-(sizeof(struct ddpehdr)+1));

	/* Create the Extended DDP header */
	ddp = (struct ddpehdr *)skb->data;
        ddp->deh_len_hops = htons(skb->len + (1<<10));
        ddp->deh_sum = 0;

	/*
         * For Localtalk we need aarp_send_ddp to strip the
         * long DDP header and place a shot DDP header on it.
         */
        if(rt->dev->type == ARPHRD_LOCALTLK)
        {
                ddp->deh_dnet  = 0;   /* FIXME more hops?? */
                ddp->deh_snet  = 0;
        }
        else
        {
                ddp->deh_dnet  = rt->at.s_net;   /* FIXME more hops?? */
                ddp->deh_snet  = our_addr->s_net;
        }
        ddp->deh_dnode = rt->at.s_node;
        ddp->deh_snode = our_addr->s_node;
        ddp->deh_dport = 72;
        ddp->deh_sport = 72;

        *((__u8 *)(ddp+1)) = 22;        	/* ddp type = IP */

        skb->protocol = htons(ETH_P_ATALK);     /* Protocol has changed */

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	aarp_send_ddp(rt->dev, skb, &rt->at, NULL);

	spin_unlock(&ipddp_route_lock);

        return NETDEV_TX_OK;
}
