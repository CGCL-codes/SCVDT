netdev_tx_t hns_nic_net_xmit_hw(struct net_device *ndev,
				struct sk_buff *skb,
				struct hns_nic_ring_data *ring_data)
{
	struct hns_nic_priv *priv = netdev_priv(ndev);
	struct hnae_ring *ring = ring_data->ring;
	struct device *dev = ring_to_dev(ring);
	struct netdev_queue *dev_queue;
	struct skb_frag_struct *frag;
	int buf_num;
	int seg_num;
	dma_addr_t dma;
	int size, next_to_use;
	int i;

	switch (priv->ops.maybe_stop_tx(&skb, &buf_num, ring)) {
	case -EBUSY:
		ring->stats.tx_busy++;
		goto out_net_tx_busy;
	case -ENOMEM:
		ring->stats.sw_err_cnt++;
		netdev_err(ndev, "no memory to xmit!\n");
		goto out_err_tx_ok;
	default:
		break;
	}

	/* no. of segments (plus a header) */
	seg_num = skb_shinfo(skb)->nr_frags + 1;
	next_to_use = ring->next_to_use;

	/* fill the first part */
	size = skb_headlen(skb);
	dma = dma_map_single(dev, skb->data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma)) {
		netdev_err(ndev, "TX head DMA map failed\n");
		ring->stats.sw_err_cnt++;
		goto out_err_tx_ok;
	}
	priv->ops.fill_desc(ring, skb, size, dma, seg_num == 1 ? 1 : 0,
			    buf_num, DESC_TYPE_SKB, ndev->mtu);

	/* fill the fragments */
	for (i = 1; i < seg_num; i++) {
		frag = &skb_shinfo(skb)->frags[i - 1];
		size = skb_frag_size(frag);
		dma = skb_frag_dma_map(dev, frag, 0, size, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma)) {
			netdev_err(ndev, "TX frag(%d) DMA map failed\n", i);
			ring->stats.sw_err_cnt++;
			goto out_map_frag_fail;
		}
		priv->ops.fill_desc(ring, skb_frag_page(frag), size, dma,
				    seg_num - 1 == i ? 1 : 0, buf_num,
				    DESC_TYPE_PAGE, ndev->mtu);
	}

	/*complete translate all packets*/
	dev_queue = netdev_get_tx_queue(ndev, skb->queue_mapping);
	netdev_tx_sent_queue(dev_queue, skb->len);

	netif_trans_update(ndev);
	ndev->stats.tx_bytes += skb->len;
	ndev->stats.tx_packets++;

	wmb(); /* commit all data before submit */
	assert(skb->queue_mapping < priv->ae_handle->q_num);
	hnae_queue_xmit(priv->ae_handle->qs[skb->queue_mapping], buf_num);
	ring->stats.tx_pkts++;
	ring->stats.tx_bytes += skb->len;

	return NETDEV_TX_OK;

out_map_frag_fail:

	while (ring->next_to_use != next_to_use) {
		unfill_desc(ring);
		if (ring->next_to_use != next_to_use)
			dma_unmap_page(dev,
				       ring->desc_cb[ring->next_to_use].dma,
				       ring->desc_cb[ring->next_to_use].length,
				       DMA_TO_DEVICE);
		else
			dma_unmap_single(dev,
					 ring->desc_cb[next_to_use].dma,
					 ring->desc_cb[next_to_use].length,
					 DMA_TO_DEVICE);
	}

out_err_tx_ok:

	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;

out_net_tx_busy:

	netif_stop_subqueue(ndev, skb->queue_mapping);

	/* Herbert's original patch had:
	 *  smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it.
	 */
	smp_mb();
	return NETDEV_TX_BUSY;
}
