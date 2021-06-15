void __skb_tstamp_tx(struct sk_buff *orig_skb,
		     struct skb_shared_hwtstamps *hwtstamps,
		     struct sock *sk, int tstype)
{
	struct sk_buff *skb;
	bool tsonly;

	if (!sk)
		return;

	tsonly = sk->sk_tsflags & SOF_TIMESTAMPING_OPT_TSONLY;
	if (!skb_may_tx_timestamp(sk, tsonly))
		return;

	if (tsonly) {
#ifdef CONFIG_INET
		if ((sk->sk_tsflags & SOF_TIMESTAMPING_OPT_STATS) &&
		    sk->sk_protocol == IPPROTO_TCP &&
		    sk->sk_type == SOCK_STREAM)
			skb = tcp_get_timestamping_opt_stats(sk);
		else
#endif
			skb = alloc_skb(0, GFP_ATOMIC);
	} else {
		skb = skb_clone(orig_skb, GFP_ATOMIC);
	}
	if (!skb)
		return;

	if (tsonly) {
		skb_shinfo(skb)->tx_flags = skb_shinfo(orig_skb)->tx_flags;
		skb_shinfo(skb)->tskey = skb_shinfo(orig_skb)->tskey;
	}

	if (hwtstamps)
		*skb_hwtstamps(skb) = *hwtstamps;
	else
		skb->tstamp = ktime_get_real();

	__skb_complete_tx_timestamp(skb, sk, tstype);
}
