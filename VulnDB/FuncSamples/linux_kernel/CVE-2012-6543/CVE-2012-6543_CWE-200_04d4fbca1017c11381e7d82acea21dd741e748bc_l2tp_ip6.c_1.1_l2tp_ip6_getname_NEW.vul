static int l2tp_ip6_getname(struct socket *sock, struct sockaddr *uaddr,
			    int *uaddr_len, int peer)
{
	struct sockaddr_l2tpip6 *lsa = (struct sockaddr_l2tpip6 *)uaddr;
	struct sock *sk = sock->sk;
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct l2tp_ip6_sock *lsk = l2tp_ip6_sk(sk);

	lsa->l2tp_family = AF_INET6;
	lsa->l2tp_flowinfo = 0;
	lsa->l2tp_scope_id = 0;
	lsa->l2tp_unused = 0;
	if (peer) {
		if (!lsk->peer_conn_id)
			return -ENOTCONN;
		lsa->l2tp_conn_id = lsk->peer_conn_id;
		lsa->l2tp_addr = np->daddr;
		if (np->sndflow)
			lsa->l2tp_flowinfo = np->flow_label;
	} else {
		if (ipv6_addr_any(&np->rcv_saddr))
			lsa->l2tp_addr = np->saddr;
		else
			lsa->l2tp_addr = np->rcv_saddr;

		lsa->l2tp_conn_id = lsk->conn_id;
	}
	if (ipv6_addr_type(&lsa->l2tp_addr) & IPV6_ADDR_LINKLOCAL)
		lsa->l2tp_scope_id = sk->sk_bound_dev_if;
	*uaddr_len = sizeof(*lsa);
	return 0;
}
