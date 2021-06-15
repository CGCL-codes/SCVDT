int dev_forward_skb(struct net_device *dev, struct sk_buff *skb)
{
	skb_orphan(skb);

	if (!(dev->flags & IFF_UP) ||
	    (skb->len > (dev->mtu + dev->hard_header_len))) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}
	skb_set_dev(skb, dev);
	skb->tstamp.tv64 = 0;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, dev);
	return netif_rx(skb);
}
