int ip6_append_data(struct sock *sk, int getfrag(void *from, char *to,
	int offset, int len, int odd, struct sk_buff *skb),
	void *from, int length, int transhdrlen,
	int hlimit, int tclass, struct ipv6_txoptions *opt, struct flowi6 *fl6,
	struct rt6_info *rt, unsigned int flags, int dontfrag)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct inet_cork *cork;
	struct sk_buff *skb, *skb_prev = NULL;
	unsigned int maxfraglen, fragheaderlen, mtu;
	int exthdrlen;
	int dst_exthdrlen;
	int hh_len;
	int copy;
	int err;
	int offset = 0;
	__u8 tx_flags = 0;

	if (flags&MSG_PROBE)
		return 0;
	cork = &inet->cork.base;
	if (skb_queue_empty(&sk->sk_write_queue)) {
		/*
		 * setup for corking
		 */
		if (opt) {
			if (WARN_ON(np->cork.opt))
				return -EINVAL;

			np->cork.opt = kzalloc(opt->tot_len, sk->sk_allocation);
			if (unlikely(np->cork.opt == NULL))
				return -ENOBUFS;

			np->cork.opt->tot_len = opt->tot_len;
			np->cork.opt->opt_flen = opt->opt_flen;
			np->cork.opt->opt_nflen = opt->opt_nflen;

			np->cork.opt->dst0opt = ip6_opt_dup(opt->dst0opt,
							    sk->sk_allocation);
			if (opt->dst0opt && !np->cork.opt->dst0opt)
				return -ENOBUFS;

			np->cork.opt->dst1opt = ip6_opt_dup(opt->dst1opt,
							    sk->sk_allocation);
			if (opt->dst1opt && !np->cork.opt->dst1opt)
				return -ENOBUFS;

			np->cork.opt->hopopt = ip6_opt_dup(opt->hopopt,
							   sk->sk_allocation);
			if (opt->hopopt && !np->cork.opt->hopopt)
				return -ENOBUFS;

			np->cork.opt->srcrt = ip6_rthdr_dup(opt->srcrt,
							    sk->sk_allocation);
			if (opt->srcrt && !np->cork.opt->srcrt)
				return -ENOBUFS;

			/* need source address above miyazawa*/
		}
		dst_hold(&rt->dst);
		cork->dst = &rt->dst;
		inet->cork.fl.u.ip6 = *fl6;
		np->cork.hop_limit = hlimit;
		np->cork.tclass = tclass;
		if (rt->dst.flags & DST_XFRM_TUNNEL)
			mtu = np->pmtudisc == IPV6_PMTUDISC_PROBE ?
			      rt->dst.dev->mtu : dst_mtu(&rt->dst);
		else
			mtu = np->pmtudisc == IPV6_PMTUDISC_PROBE ?
			      rt->dst.dev->mtu : dst_mtu(rt->dst.path);
		if (np->frag_size < mtu) {
			if (np->frag_size)
				mtu = np->frag_size;
		}
		cork->fragsize = mtu;
		if (dst_allfrag(rt->dst.path))
			cork->flags |= IPCORK_ALLFRAG;
		cork->length = 0;
		exthdrlen = (opt ? opt->opt_flen : 0);
		length += exthdrlen;
		transhdrlen += exthdrlen;
		dst_exthdrlen = rt->dst.header_len - rt->rt6i_nfheader_len;
	} else {
		rt = (struct rt6_info *)cork->dst;
		fl6 = &inet->cork.fl.u.ip6;
		opt = np->cork.opt;
		transhdrlen = 0;
		exthdrlen = 0;
		dst_exthdrlen = 0;
		mtu = cork->fragsize;
	}

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	fragheaderlen = sizeof(struct ipv6hdr) + rt->rt6i_nfheader_len +
			(opt ? opt->opt_nflen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen - sizeof(struct frag_hdr);

	if (mtu <= sizeof(struct ipv6hdr) + IPV6_MAXPLEN) {
		if (cork->length + length > sizeof(struct ipv6hdr) + IPV6_MAXPLEN - fragheaderlen) {
			ipv6_local_error(sk, EMSGSIZE, fl6, mtu-exthdrlen);
			return -EMSGSIZE;
		}
	}

	/* For UDP, check if TX timestamp is enabled */
	if (sk->sk_type == SOCK_DGRAM)
		sock_tx_timestamp(sk, &tx_flags);

	/*
	 * Let's try using as much space as possible.
	 * Use MTU if total length of the message fits into the MTU.
	 * Otherwise, we need to reserve fragment header and
	 * fragment alignment (= 8-15 octects, in total).
	 *
	 * Note that we may need to "move" the data from the tail of
	 * of the buffer to the new fragment when we split
	 * the message.
	 *
	 * FIXME: It may be fragmented into multiple chunks
	 *        at once if non-fragmentable extension headers
	 *        are too large.
	 * --yoshfuji
	 */

	if ((length > mtu) && dontfrag && (sk->sk_protocol == IPPROTO_UDP ||
					   sk->sk_protocol == IPPROTO_RAW)) {
		ipv6_local_rxpmtu(sk, fl6, mtu-exthdrlen);
		return -EMSGSIZE;
	}

	skb = skb_peek_tail(&sk->sk_write_queue);
	cork->length += length;
	if (((length > mtu) ||
	     (skb && skb_is_gso(skb))) &&
	    (sk->sk_protocol == IPPROTO_UDP) &&
	    (rt->dst.dev->features & NETIF_F_UFO)) {
		err = ip6_ufo_append_data(sk, getfrag, from, length,
					  hh_len, fragheaderlen,
					  transhdrlen, mtu, flags, rt);
		if (err)
			goto error;
		return 0;
	}

	if (!skb)
		goto alloc_new_skb;

	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
		copy = (cork->length <= mtu && !(cork->flags & IPCORK_ALLFRAG) ? mtu : maxfraglen) - skb->len;
		if (copy < length)
			copy = maxfraglen - skb->len;

		if (copy <= 0) {
			char *data;
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen;
alloc_new_skb:
			/* There's no room in the current skb */
			if (skb)
				fraggap = skb->len - maxfraglen;
			else
				fraggap = 0;
			/* update mtu and maxfraglen if necessary */
			if (skb == NULL || skb_prev == NULL)
				ip6_append_data_mtu(&mtu, &maxfraglen,
						    fragheaderlen, skb, rt,
						    np->pmtudisc ==
						    IPV6_PMTUDISC_PROBE);

			skb_prev = skb;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			datalen = length + fraggap;

			if (datalen > (cork->length <= mtu && !(cork->flags & IPCORK_ALLFRAG) ? mtu : maxfraglen) - fragheaderlen)
				datalen = maxfraglen - fragheaderlen - rt->dst.trailer_len;
			if ((flags & MSG_MORE) &&
			    !(rt->dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else
				alloclen = datalen + fragheaderlen;

			alloclen += dst_exthdrlen;

			if (datalen != length + fraggap) {
				/*
				 * this is not the last fragment, the trailer
				 * space is regarded as data space.
				 */
				datalen += rt->dst.trailer_len;
			}

			alloclen += rt->dst.trailer_len;
			fraglen = datalen + fragheaderlen;

			/*
			 * We just reserve space for fragment header.
			 * Note: this may be overallocation if the message
			 * (without MSG_MORE) fits into the MTU.
			 */
			alloclen += sizeof(struct frag_hdr);

			if (transhdrlen) {
				skb = sock_alloc_send_skb(sk,
						alloclen + hh_len,
						(flags & MSG_DONTWAIT), &err);
			} else {
				skb = NULL;
				if (atomic_read(&sk->sk_wmem_alloc) <=
				    2 * sk->sk_sndbuf)
					skb = sock_wmalloc(sk,
							   alloclen + hh_len, 1,
							   sk->sk_allocation);
				if (unlikely(skb == NULL))
					err = -ENOBUFS;
				else {
					/* Only the initial fragment
					 * is time stamped.
					 */
					tx_flags = 0;
				}
			}
			if (skb == NULL)
				goto error;
			/*
			 *	Fill in the control structures
			 */
			skb->protocol = htons(ETH_P_IPV6);
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			/* reserve for fragmentation and ipsec header */
			skb_reserve(skb, hh_len + sizeof(struct frag_hdr) +
				    dst_exthdrlen);

			if (sk->sk_type == SOCK_DGRAM)
				skb_shinfo(skb)->tx_flags = tx_flags;

			/*
			 *	Find where to start putting bytes
			 */
			data = skb_put(skb, fraglen);
			skb_set_network_header(skb, exthdrlen);
			data += fragheaderlen;
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				pskb_trim_unique(skb_prev, maxfraglen);
			}
			copy = datalen - transhdrlen - fraggap;

			if (copy < 0) {
				err = -EINVAL;
				kfree_skb(skb);
				goto error;
			} else if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			offset += copy;
			length -= datalen - fraggap;
			transhdrlen = 0;
			exthdrlen = 0;
			dst_exthdrlen = 0;

			/*
			 * Put the packet on the pending queue
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		if (copy > length)
			copy = length;

		if (!(rt->dst.dev->features&NETIF_F_SG)) {
			unsigned int off;

			off = skb->len;
			if (getfrag(from, skb_put(skb, copy),
						offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else {
			int i = skb_shinfo(skb)->nr_frags;
			struct page_frag *pfrag = sk_page_frag(sk);

			err = -ENOMEM;
			if (!sk_page_frag_refill(sk, pfrag))
				goto error;

			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) {
				err = -EMSGSIZE;
				if (i == MAX_SKB_FRAGS)
					goto error;

				__skb_fill_page_desc(skb, i, pfrag->page,
						     pfrag->offset, 0);
				skb_shinfo(skb)->nr_frags = ++i;
				get_page(pfrag->page);
			}
			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			if (getfrag(from,
				    page_address(pfrag->page) + pfrag->offset,
				    offset, copy, skb->len, skb) < 0)
				goto error_efault;

			pfrag->offset += copy;
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			atomic_add(copy, &sk->sk_wmem_alloc);
		}
		offset += copy;
		length -= copy;
	}

	return 0;

error_efault:
	err = -EFAULT;
error:
	cork->length -= length;
	IP6_INC_STATS(sock_net(sk), rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
	return err;
}
