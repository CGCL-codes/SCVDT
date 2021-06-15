static int tcp_v6_send_synack(const struct sock *sk, struct dst_entry *dst,
			      struct flowi *fl,
			      struct request_sock *req,
			      struct tcp_fastopen_cookie *foc,
			      bool attach_req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct flowi6 *fl6 = &fl->u.ip6;
	struct sk_buff *skb;
	int err = -ENOMEM;

	/* First, grab a route. */
	if (!dst && (dst = inet6_csk_route_req(sk, fl6, req,
					       IPPROTO_TCP)) == NULL)
		goto done;

	skb = tcp_make_synack(sk, dst, req, foc, attach_req);

	if (skb) {
		__tcp_v6_send_check(skb, &ireq->ir_v6_loc_addr,
				    &ireq->ir_v6_rmt_addr);

		fl6->daddr = ireq->ir_v6_rmt_addr;
		if (np->repflow && ireq->pktopts)
			fl6->flowlabel = ip6_flowlabel(ipv6_hdr(ireq->pktopts));

		err = ip6_xmit(sk, skb, fl6, rcu_dereference(np->opt),
			       np->tclass);
		err = net_xmit_eval(err);
	}

done:
	return err;
}
