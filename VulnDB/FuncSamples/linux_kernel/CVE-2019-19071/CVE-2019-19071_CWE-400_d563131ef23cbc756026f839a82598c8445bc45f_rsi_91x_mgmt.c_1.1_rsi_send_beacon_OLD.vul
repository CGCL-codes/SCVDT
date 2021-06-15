static int rsi_send_beacon(struct rsi_common *common)
{
	struct sk_buff *skb = NULL;
	u8 dword_align_bytes = 0;

	skb = dev_alloc_skb(MAX_MGMT_PKT_SIZE);
	if (!skb)
		return -ENOMEM;

	memset(skb->data, 0, MAX_MGMT_PKT_SIZE);

	dword_align_bytes = ((unsigned long)skb->data & 0x3f);
	if (dword_align_bytes)
		skb_pull(skb, (64 - dword_align_bytes));
	if (rsi_prepare_beacon(common, skb)) {
		rsi_dbg(ERR_ZONE, "Failed to prepare beacon\n");
		return -EINVAL;
	}
	skb_queue_tail(&common->tx_queue[MGMT_BEACON_Q], skb);
	rsi_set_event(&common->tx_thread.event);
	rsi_dbg(DATA_TX_ZONE, "%s: Added to beacon queue\n", __func__);

	return 0;
}
