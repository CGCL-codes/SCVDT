static int handle_ip_over_ddp(struct sk_buff *skb)
{
	struct net_device *dev = __dev_get_by_name(&init_net, "ipddp0");
	struct net_device_stats *stats;

	/* This needs to be able to handle ipddp"N" devices */
	if (!dev) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	skb->protocol = htons(ETH_P_IP);
	skb_pull(skb, 13);
	skb->dev   = dev;
	skb_reset_transport_header(skb);

	stats = netdev_priv(dev);
	stats->rx_packets++;
	stats->rx_bytes += skb->len + 13;
	return netif_rx(skb);  /* Send the SKB up to a higher place. */
}
