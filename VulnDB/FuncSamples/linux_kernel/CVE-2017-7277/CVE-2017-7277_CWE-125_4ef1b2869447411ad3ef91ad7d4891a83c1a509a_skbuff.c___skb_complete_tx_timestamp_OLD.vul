static void __skb_complete_tx_timestamp(struct sk_buff *skb,
					struct sock *sk,
					int tstype)
{
	struct sock_exterr_skb *serr;
	int err;

	serr = SKB_EXT_ERR(skb);
	memset(serr, 0, sizeof(*serr));
	serr->ee.ee_errno = ENOMSG;
	serr->ee.ee_origin = SO_EE_ORIGIN_TIMESTAMPING;
	serr->ee.ee_info = tstype;
	if (sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID) {
		serr->ee.ee_data = skb_shinfo(skb)->tskey;
		if (sk->sk_protocol == IPPROTO_TCP &&
		    sk->sk_type == SOCK_STREAM)
			serr->ee.ee_data -= sk->sk_tskey;
	}

	err = sock_queue_err_skb(sk, skb);

	if (err)
		kfree_skb(skb);
}
