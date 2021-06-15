int nfc_llcp_send_cc(struct nfc_llcp_sock *sock)
{
	struct nfc_llcp_local *local;
	struct sk_buff *skb;
	u8 *miux_tlv = NULL, miux_tlv_length;
	u8 *rw_tlv = NULL, rw_tlv_length, rw;
	int err;
	u16 size = 0;
	__be16 miux;

	pr_debug("Sending CC\n");

	local = sock->local;
	if (local == NULL)
		return -ENODEV;

	/* If the socket parameters are not set, use the local ones */
	miux = be16_to_cpu(sock->miux) > LLCP_MAX_MIUX ?
		local->miux : sock->miux;
	rw = sock->rw > LLCP_MAX_RW ? local->rw : sock->rw;

	miux_tlv = nfc_llcp_build_tlv(LLCP_TLV_MIUX, (u8 *)&miux, 0,
				      &miux_tlv_length);
	if (!miux_tlv) {
		err = -ENOMEM;
		goto error_tlv;
	}
	size += miux_tlv_length;

	rw_tlv = nfc_llcp_build_tlv(LLCP_TLV_RW, &rw, 0, &rw_tlv_length);
	if (!rw_tlv) {
		err = -ENOMEM;
		goto error_tlv;
	}
	size += rw_tlv_length;

	skb = llcp_allocate_pdu(sock, LLCP_PDU_CC, size);
	if (skb == NULL) {
		err = -ENOMEM;
		goto error_tlv;
	}

	llcp_add_tlv(skb, miux_tlv, miux_tlv_length);
	llcp_add_tlv(skb, rw_tlv, rw_tlv_length);

	skb_queue_tail(&local->tx_queue, skb);

	err = 0;

error_tlv:
	if (err)
		pr_err("error %d\n", err);

	kfree(miux_tlv);
	kfree(rw_tlv);

	return err;
}
