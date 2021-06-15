static void can_can_gw_rcv(struct sk_buff *skb, void *data)
{
	struct cgw_job *gwj = (struct cgw_job *)data;
	struct can_frame *cf;
	struct sk_buff *nskb;
	int modidx = 0;

	/*
	 * Do not handle CAN frames routed more than 'max_hops' times.
	 * In general we should never catch this delimiter which is intended
	 * to cover a misconfiguration protection (e.g. circular CAN routes).
	 *
	 * The Controller Area Network controllers only accept CAN frames with
	 * correct CRCs - which are not visible in the controller registers.
	 * According to skbuff.h documentation the csum_start element for IP
	 * checksums is undefined/unused when ip_summed == CHECKSUM_UNNECESSARY.
	 * Only CAN skbs can be processed here which already have this property.
	 */

#define cgw_hops(skb) ((skb)->csum_start)

	BUG_ON(skb->ip_summed != CHECKSUM_UNNECESSARY);

	if (cgw_hops(skb) >= max_hops) {
		/* indicate deleted frames due to misconfiguration */
		gwj->deleted_frames++;
		return;
	}

	if (!(gwj->dst.dev->flags & IFF_UP)) {
		gwj->dropped_frames++;
		return;
	}

	/* is sending the skb back to the incoming interface not allowed? */
	if (!(gwj->flags & CGW_FLAGS_CAN_IIF_TX_OK) &&
	    can_skb_prv(skb)->ifindex == gwj->dst.dev->ifindex)
		return;

	/*
	 * clone the given skb, which has not been done in can_rcv()
	 *
	 * When there is at least one modification function activated,
	 * we need to copy the skb as we want to modify skb->data.
	 */
	if (gwj->mod.modfunc[0])
		nskb = skb_copy(skb, GFP_ATOMIC);
	else
		nskb = skb_clone(skb, GFP_ATOMIC);

	if (!nskb) {
		gwj->dropped_frames++;
		return;
	}

	/* put the incremented hop counter in the cloned skb */
	cgw_hops(nskb) = cgw_hops(skb) + 1;

	/* first processing of this CAN frame -> adjust to private hop limit */
	if (gwj->limit_hops && cgw_hops(nskb) == 1)
		cgw_hops(nskb) = max_hops - gwj->limit_hops + 1;

	nskb->dev = gwj->dst.dev;

	/* pointer to modifiable CAN frame */
	cf = (struct can_frame *)nskb->data;

	/* perform preprocessed modification functions if there are any */
	while (modidx < MAX_MODFUNCTIONS && gwj->mod.modfunc[modidx])
		(*gwj->mod.modfunc[modidx++])(cf, &gwj->mod);

	/* Has the CAN frame been modified? */
	if (modidx) {
		/* get available space for the processed CAN frame type */
		int max_len = nskb->len - offsetof(struct can_frame, data);

		/* dlc may have changed, make sure it fits to the CAN frame */
		if (cf->can_dlc > max_len)
			goto out_delete;

		/* check for checksum updates in classic CAN length only */
		if (gwj->mod.csumfunc.crc8) {
			if (cf->can_dlc > 8)
				goto out_delete;

			(*gwj->mod.csumfunc.crc8)(cf, &gwj->mod.csum.crc8);
		}

		if (gwj->mod.csumfunc.xor) {
			if (cf->can_dlc > 8)
				goto out_delete;

			(*gwj->mod.csumfunc.xor)(cf, &gwj->mod.csum.xor);
		}
	}

	/* clear the skb timestamp if not configured the other way */
	if (!(gwj->flags & CGW_FLAGS_CAN_SRC_TSTAMP))
		nskb->tstamp = 0;

	/* send to netdevice */
	if (can_send(nskb, gwj->flags & CGW_FLAGS_CAN_ECHO))
		gwj->dropped_frames++;
	else
		gwj->handled_frames++;

	return;

 out_delete:
	/* delete frame due to misconfiguration */
	gwj->deleted_frames++;
	kfree_skb(nskb);
	return;
}
