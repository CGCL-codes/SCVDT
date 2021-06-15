static int atalk_rcv(struct sk_buff *skb, struct net_device *dev,
		     struct packet_type *pt, struct net_device *orig_dev)
{
	struct ddpehdr *ddp;
	struct sock *sock;
	struct atalk_iface *atif;
	struct sockaddr_at tosat;
	int origlen;
	__u16 len_hops;

	if (!net_eq(dev_net(dev), &init_net))
		goto drop;

	/* Don't mangle buffer if shared */
	if (!(skb = skb_share_check(skb, GFP_ATOMIC)))
		goto out;

	/* Size check and make sure header is contiguous */
	if (!pskb_may_pull(skb, sizeof(*ddp)))
		goto drop;

	ddp = ddp_hdr(skb);

	len_hops = ntohs(ddp->deh_len_hops);

	/* Trim buffer in case of stray trailing data */
	origlen = skb->len;
	skb_trim(skb, min_t(unsigned int, skb->len, len_hops & 1023));

	/*
	 * Size check to see if ddp->deh_len was crap
	 * (Otherwise we'll detonate most spectacularly
	 * in the middle of atalk_checksum() or recvmsg()).
	 */
	if (skb->len < sizeof(*ddp) || skb->len < (len_hops & 1023)) {
		pr_debug("AppleTalk: dropping corrupted frame (deh_len=%u, "
			 "skb->len=%u)\n", len_hops & 1023, skb->len);
		goto drop;
	}

	/*
	 * Any checksums. Note we don't do htons() on this == is assumed to be
	 * valid for net byte orders all over the networking code...
	 */
	if (ddp->deh_sum &&
	    atalk_checksum(skb, len_hops & 1023) != ddp->deh_sum)
		/* Not a valid AppleTalk frame - dustbin time */
		goto drop;

	/* Check the packet is aimed at us */
	if (!ddp->deh_dnet)	/* Net 0 is 'this network' */
		atif = atalk_find_anynet(ddp->deh_dnode, dev);
	else
		atif = atalk_find_interface(ddp->deh_dnet, ddp->deh_dnode);

	if (!atif) {
		/* Not ours, so we route the packet via the correct
		 * AppleTalk iface
		 */
		return atalk_route_packet(skb, dev, ddp, len_hops, origlen);
	}

	/* if IP over DDP is not selected this code will be optimized out */
	if (is_ip_over_ddp(skb))
		return handle_ip_over_ddp(skb);
	/*
	 * Which socket - atalk_search_socket() looks for a *full match*
	 * of the <net, node, port> tuple.
	 */
	tosat.sat_addr.s_net  = ddp->deh_dnet;
	tosat.sat_addr.s_node = ddp->deh_dnode;
	tosat.sat_port	      = ddp->deh_dport;

	sock = atalk_search_socket(&tosat, atif);
	if (!sock) /* But not one of our sockets */
		goto drop;

	/* Queue packet (standard) */
	skb->sk = sock;

	if (sock_queue_rcv_skb(sock, skb) < 0)
		goto drop;

	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;

}
