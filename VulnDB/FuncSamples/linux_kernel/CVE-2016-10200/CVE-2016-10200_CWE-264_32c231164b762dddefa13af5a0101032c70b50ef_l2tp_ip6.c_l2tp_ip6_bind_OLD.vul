static int l2tp_ip6_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sockaddr_l2tpip6 *addr = (struct sockaddr_l2tpip6 *) uaddr;
	struct net *net = sock_net(sk);
	__be32 v4addr = 0;
	int addr_type;
	int err;

	if (!sock_flag(sk, SOCK_ZAPPED))
		return -EINVAL;
	if (addr->l2tp_family != AF_INET6)
		return -EINVAL;
	if (addr_len < sizeof(*addr))
		return -EINVAL;

	addr_type = ipv6_addr_type(&addr->l2tp_addr);

	/* l2tp_ip6 sockets are IPv6 only */
	if (addr_type == IPV6_ADDR_MAPPED)
		return -EADDRNOTAVAIL;

	/* L2TP is point-point, not multicast */
	if (addr_type & IPV6_ADDR_MULTICAST)
		return -EADDRNOTAVAIL;

	err = -EADDRINUSE;
	read_lock_bh(&l2tp_ip6_lock);
	if (__l2tp_ip6_bind_lookup(net, &addr->l2tp_addr,
				   sk->sk_bound_dev_if, addr->l2tp_conn_id))
		goto out_in_use;
	read_unlock_bh(&l2tp_ip6_lock);

	lock_sock(sk);

	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE)
		goto out_unlock;

	/* Check if the address belongs to the host. */
	rcu_read_lock();
	if (addr_type != IPV6_ADDR_ANY) {
		struct net_device *dev = NULL;

		if (addr_type & IPV6_ADDR_LINKLOCAL) {
			if (addr_len >= sizeof(struct sockaddr_in6) &&
			    addr->l2tp_scope_id) {
				/* Override any existing binding, if another
				 * one is supplied by user.
				 */
				sk->sk_bound_dev_if = addr->l2tp_scope_id;
			}

			/* Binding to link-local address requires an
			   interface */
			if (!sk->sk_bound_dev_if)
				goto out_unlock_rcu;

			err = -ENODEV;
			dev = dev_get_by_index_rcu(sock_net(sk),
						   sk->sk_bound_dev_if);
			if (!dev)
				goto out_unlock_rcu;
		}

		/* ipv4 addr of the socket is invalid.  Only the
		 * unspecified and mapped address have a v4 equivalent.
		 */
		v4addr = LOOPBACK4_IPV6;
		err = -EADDRNOTAVAIL;
		if (!ipv6_chk_addr(sock_net(sk), &addr->l2tp_addr, dev, 0))
			goto out_unlock_rcu;
	}
	rcu_read_unlock();

	inet->inet_rcv_saddr = inet->inet_saddr = v4addr;
	sk->sk_v6_rcv_saddr = addr->l2tp_addr;
	np->saddr = addr->l2tp_addr;

	l2tp_ip6_sk(sk)->conn_id = addr->l2tp_conn_id;

	write_lock_bh(&l2tp_ip6_lock);
	sk_add_bind_node(sk, &l2tp_ip6_bind_table);
	sk_del_node_init(sk);
	write_unlock_bh(&l2tp_ip6_lock);

	sock_reset_flag(sk, SOCK_ZAPPED);
	release_sock(sk);
	return 0;

out_unlock_rcu:
	rcu_read_unlock();
out_unlock:
	release_sock(sk);
	return err;

out_in_use:
	read_unlock_bh(&l2tp_ip6_lock);
	return err;
}
