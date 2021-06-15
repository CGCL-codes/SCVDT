static int tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
		       struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;
	struct packet_sock *po;
	struct sockaddr_ll *sll;
	union tpacket_uhdr h;
	u8 *skb_head = skb->data;
	int skb_len = skb->len;
	unsigned int snaplen, res;
	unsigned long status = TP_STATUS_USER;
	unsigned short macoff, netoff, hdrlen;
	struct sk_buff *copy_skb = NULL;
	struct timespec ts;
	__u32 ts_status;
	bool is_drop_n_account = false;
	bool do_vnet = false;

	/* struct tpacket{2,3}_hdr is aligned to a multiple of TPACKET_ALIGNMENT.
	 * We may add members to them until current aligned size without forcing
	 * userspace to call getsockopt(..., PACKET_HDRLEN, ...).
	 */
	BUILD_BUG_ON(TPACKET_ALIGN(sizeof(*h.h2)) != 32);
	BUILD_BUG_ON(TPACKET_ALIGN(sizeof(*h.h3)) != 48);

	if (skb->pkt_type == PACKET_LOOPBACK)
		goto drop;

	sk = pt->af_packet_priv;
	po = pkt_sk(sk);

	if (!net_eq(dev_net(dev), sock_net(sk)))
		goto drop;

	if (dev->header_ops) {
		if (sk->sk_type != SOCK_DGRAM)
			skb_push(skb, skb->data - skb_mac_header(skb));
		else if (skb->pkt_type == PACKET_OUTGOING) {
			/* Special case: outgoing packets have ll header at head */
			skb_pull(skb, skb_network_offset(skb));
		}
	}

	snaplen = skb->len;

	res = run_filter(skb, sk, snaplen);
	if (!res)
		goto drop_n_restore;

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		status |= TP_STATUS_CSUMNOTREADY;
	else if (skb->pkt_type != PACKET_OUTGOING &&
		 (skb->ip_summed == CHECKSUM_COMPLETE ||
		  skb_csum_unnecessary(skb)))
		status |= TP_STATUS_CSUM_VALID;

	if (snaplen > res)
		snaplen = res;

	if (sk->sk_type == SOCK_DGRAM) {
		macoff = netoff = TPACKET_ALIGN(po->tp_hdrlen) + 16 +
				  po->tp_reserve;
	} else {
		unsigned int maclen = skb_network_offset(skb);
		netoff = TPACKET_ALIGN(po->tp_hdrlen +
				       (maclen < 16 ? 16 : maclen)) +
				       po->tp_reserve;
		if (po->has_vnet_hdr) {
			netoff += sizeof(struct virtio_net_hdr);
			do_vnet = true;
		}
		macoff = netoff - maclen;
	}
	if (po->tp_version <= TPACKET_V2) {
		if (macoff + snaplen > po->rx_ring.frame_size) {
			if (po->copy_thresh &&
			    atomic_read(&sk->sk_rmem_alloc) < sk->sk_rcvbuf) {
				if (skb_shared(skb)) {
					copy_skb = skb_clone(skb, GFP_ATOMIC);
				} else {
					copy_skb = skb_get(skb);
					skb_head = skb->data;
				}
				if (copy_skb)
					skb_set_owner_r(copy_skb, sk);
			}
			snaplen = po->rx_ring.frame_size - macoff;
			if ((int)snaplen < 0) {
				snaplen = 0;
				do_vnet = false;
			}
		}
	} else if (unlikely(macoff + snaplen >
			    GET_PBDQC_FROM_RB(&po->rx_ring)->max_frame_len)) {
		u32 nval;

		nval = GET_PBDQC_FROM_RB(&po->rx_ring)->max_frame_len - macoff;
		pr_err_once("tpacket_rcv: packet too big, clamped from %u to %u. macoff=%u\n",
			    snaplen, nval, macoff);
		snaplen = nval;
		if (unlikely((int)snaplen < 0)) {
			snaplen = 0;
			macoff = GET_PBDQC_FROM_RB(&po->rx_ring)->max_frame_len;
			do_vnet = false;
		}
	}
	spin_lock(&sk->sk_receive_queue.lock);
	h.raw = packet_current_rx_frame(po, skb,
					TP_STATUS_KERNEL, (macoff+snaplen));
	if (!h.raw)
		goto drop_n_account;
	if (po->tp_version <= TPACKET_V2) {
		packet_increment_rx_head(po, &po->rx_ring);
	/*
	 * LOSING will be reported till you read the stats,
	 * because it's COR - Clear On Read.
	 * Anyways, moving it for V1/V2 only as V3 doesn't need this
	 * at packet level.
	 */
		if (po->stats.stats1.tp_drops)
			status |= TP_STATUS_LOSING;
	}
	po->stats.stats1.tp_packets++;
	if (copy_skb) {
		status |= TP_STATUS_COPY;
		__skb_queue_tail(&sk->sk_receive_queue, copy_skb);
	}
	spin_unlock(&sk->sk_receive_queue.lock);

	if (do_vnet) {
		if (virtio_net_hdr_from_skb(skb, h.raw + macoff -
					    sizeof(struct virtio_net_hdr),
					    vio_le(), true)) {
			spin_lock(&sk->sk_receive_queue.lock);
			goto drop_n_account;
		}
	}

	skb_copy_bits(skb, 0, h.raw + macoff, snaplen);

	if (!(ts_status = tpacket_get_timestamp(skb, &ts, po->tp_tstamp)))
		getnstimeofday(&ts);

	status |= ts_status;

	switch (po->tp_version) {
	case TPACKET_V1:
		h.h1->tp_len = skb->len;
		h.h1->tp_snaplen = snaplen;
		h.h1->tp_mac = macoff;
		h.h1->tp_net = netoff;
		h.h1->tp_sec = ts.tv_sec;
		h.h1->tp_usec = ts.tv_nsec / NSEC_PER_USEC;
		hdrlen = sizeof(*h.h1);
		break;
	case TPACKET_V2:
		h.h2->tp_len = skb->len;
		h.h2->tp_snaplen = snaplen;
		h.h2->tp_mac = macoff;
		h.h2->tp_net = netoff;
		h.h2->tp_sec = ts.tv_sec;
		h.h2->tp_nsec = ts.tv_nsec;
		if (skb_vlan_tag_present(skb)) {
			h.h2->tp_vlan_tci = skb_vlan_tag_get(skb);
			h.h2->tp_vlan_tpid = ntohs(skb->vlan_proto);
			status |= TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID;
		} else {
			h.h2->tp_vlan_tci = 0;
			h.h2->tp_vlan_tpid = 0;
		}
		memset(h.h2->tp_padding, 0, sizeof(h.h2->tp_padding));
		hdrlen = sizeof(*h.h2);
		break;
	case TPACKET_V3:
		/* tp_nxt_offset,vlan are already populated above.
		 * So DONT clear those fields here
		 */
		h.h3->tp_status |= status;
		h.h3->tp_len = skb->len;
		h.h3->tp_snaplen = snaplen;
		h.h3->tp_mac = macoff;
		h.h3->tp_net = netoff;
		h.h3->tp_sec  = ts.tv_sec;
		h.h3->tp_nsec = ts.tv_nsec;
		memset(h.h3->tp_padding, 0, sizeof(h.h3->tp_padding));
		hdrlen = sizeof(*h.h3);
		break;
	default:
		BUG();
	}

	sll = h.raw + TPACKET_ALIGN(hdrlen);
	sll->sll_halen = dev_parse_header(skb, sll->sll_addr);
	sll->sll_family = AF_PACKET;
	sll->sll_hatype = dev->type;
	sll->sll_protocol = skb->protocol;
	sll->sll_pkttype = skb->pkt_type;
	if (unlikely(po->origdev))
		sll->sll_ifindex = orig_dev->ifindex;
	else
		sll->sll_ifindex = dev->ifindex;

	smp_mb();

#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE == 1
	if (po->tp_version <= TPACKET_V2) {
		u8 *start, *end;

		end = (u8 *) PAGE_ALIGN((unsigned long) h.raw +
					macoff + snaplen);

		for (start = h.raw; start < end; start += PAGE_SIZE)
			flush_dcache_page(pgv_to_page(start));
	}
	smp_wmb();
#endif

	if (po->tp_version <= TPACKET_V2) {
		__packet_set_status(po, h.raw, status);
		sk->sk_data_ready(sk);
	} else {
		prb_clear_blk_fill_status(&po->rx_ring);
	}

drop_n_restore:
	if (skb_head != skb->data && skb_shared(skb)) {
		skb->data = skb_head;
		skb->len = skb_len;
	}
drop:
	if (!is_drop_n_account)
		consume_skb(skb);
	else
		kfree_skb(skb);
	return 0;

drop_n_account:
	is_drop_n_account = true;
	po->stats.stats1.tp_drops++;
	spin_unlock(&sk->sk_receive_queue.lock);

	sk->sk_data_ready(sk);
	kfree_skb(copy_skb);
	goto drop_n_restore;
}
