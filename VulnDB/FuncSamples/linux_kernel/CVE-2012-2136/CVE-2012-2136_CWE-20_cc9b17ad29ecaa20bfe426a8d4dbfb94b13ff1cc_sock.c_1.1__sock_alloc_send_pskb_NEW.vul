struct sk_buff *sock_alloc_send_pskb(struct sock *sk, unsigned long header_len,
				     unsigned long data_len, int noblock,
				     int *errcode)
{
	struct sk_buff *skb;
	gfp_t gfp_mask;
	long timeo;
	int err;
	int npages = (data_len + (PAGE_SIZE - 1)) >> PAGE_SHIFT;

	err = -EMSGSIZE;
	if (npages > MAX_SKB_FRAGS)
		goto failure;

	gfp_mask = sk->sk_allocation;
	if (gfp_mask & __GFP_WAIT)
		gfp_mask |= __GFP_REPEAT;

	timeo = sock_sndtimeo(sk, noblock);
	while (1) {
		err = sock_error(sk);
		if (err != 0)
			goto failure;

		err = -EPIPE;
		if (sk->sk_shutdown & SEND_SHUTDOWN)
			goto failure;

		if (atomic_read(&sk->sk_wmem_alloc) < sk->sk_sndbuf) {
			skb = alloc_skb(header_len, gfp_mask);
			if (skb) {
				int i;

				/* No pages, we're done... */
				if (!data_len)
					break;

				skb->truesize += data_len;
				skb_shinfo(skb)->nr_frags = npages;
				for (i = 0; i < npages; i++) {
					struct page *page;

					page = alloc_pages(sk->sk_allocation, 0);
					if (!page) {
						err = -ENOBUFS;
						skb_shinfo(skb)->nr_frags = i;
						kfree_skb(skb);
						goto failure;
					}

					__skb_fill_page_desc(skb, i,
							page, 0,
							(data_len >= PAGE_SIZE ?
							 PAGE_SIZE :
							 data_len));
					data_len -= PAGE_SIZE;
				}

				/* Full success... */
				break;
			}
			err = -ENOBUFS;
			goto failure;
		}
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		err = -EAGAIN;
		if (!timeo)
			goto failure;
		if (signal_pending(current))
			goto interrupted;
		timeo = sock_wait_for_wmem(sk, timeo);
	}

	skb_set_owner_w(skb, sk);
	return skb;

interrupted:
	err = sock_intr_errno(timeo);
failure:
	*errcode = err;
	return NULL;
}
