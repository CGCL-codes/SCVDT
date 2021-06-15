static int pptp_connect(struct socket *sock, struct sockaddr *uservaddr,
	int sockaddr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_pppox *sp = (struct sockaddr_pppox *) uservaddr;
	struct pppox_sock *po = pppox_sk(sk);
	struct pptp_opt *opt = &po->proto.pptp;
	struct rtable *rt;
	struct flowi4 fl4;
	int error = 0;

	if (sp->sa_protocol != PX_PROTO_PPTP)
		return -EINVAL;

	if (lookup_chan_dst(sp->sa_addr.pptp.call_id, sp->sa_addr.pptp.sin_addr.s_addr))
		return -EALREADY;

	lock_sock(sk);
	/* Check for already bound sockets */
	if (sk->sk_state & PPPOX_CONNECTED) {
		error = -EBUSY;
		goto end;
	}

	/* Check for already disconnected sockets, on attempts to disconnect */
	if (sk->sk_state & PPPOX_DEAD) {
		error = -EALREADY;
		goto end;
	}

	if (!opt->src_addr.sin_addr.s_addr || !sp->sa_addr.pptp.sin_addr.s_addr) {
		error = -EINVAL;
		goto end;
	}

	po->chan.private = sk;
	po->chan.ops = &pptp_chan_ops;

	rt = ip_route_output_ports(sock_net(sk), &fl4, sk,
				   opt->dst_addr.sin_addr.s_addr,
				   opt->src_addr.sin_addr.s_addr,
				   0, 0,
				   IPPROTO_GRE, RT_CONN_FLAGS(sk), 0);
	if (IS_ERR(rt)) {
		error = -EHOSTUNREACH;
		goto end;
	}
	sk_setup_caps(sk, &rt->dst);

	po->chan.mtu = dst_mtu(&rt->dst);
	if (!po->chan.mtu)
		po->chan.mtu = PPP_MRU;
	ip_rt_put(rt);
	po->chan.mtu -= PPTP_HEADER_OVERHEAD;

	po->chan.hdrlen = 2 + sizeof(struct pptp_gre_header);
	error = ppp_register_channel(&po->chan);
	if (error) {
		pr_err("PPTP: failed to register PPP channel (%d)\n", error);
		goto end;
	}

	opt->dst_addr = sp->sa_addr.pptp;
	sk->sk_state = PPPOX_CONNECTED;

 end:
	release_sock(sk);
	return error;
}
