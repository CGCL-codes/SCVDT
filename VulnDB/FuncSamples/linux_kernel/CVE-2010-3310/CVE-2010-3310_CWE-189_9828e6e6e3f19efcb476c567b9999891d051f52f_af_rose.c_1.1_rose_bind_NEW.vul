static int rose_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;
	struct rose_sock *rose = rose_sk(sk);
	struct sockaddr_rose *addr = (struct sockaddr_rose *)uaddr;
	struct net_device *dev;
	ax25_address *source;
	ax25_uid_assoc *user;
	int n;

	if (!sock_flag(sk, SOCK_ZAPPED))
		return -EINVAL;

	if (addr_len != sizeof(struct sockaddr_rose) && addr_len != sizeof(struct full_sockaddr_rose))
		return -EINVAL;

	if (addr->srose_family != AF_ROSE)
		return -EINVAL;

	if (addr_len == sizeof(struct sockaddr_rose) && addr->srose_ndigis > 1)
		return -EINVAL;

	if ((unsigned int) addr->srose_ndigis > ROSE_MAX_DIGIS)
		return -EINVAL;

	if ((dev = rose_dev_get(&addr->srose_addr)) == NULL) {
		SOCK_DEBUG(sk, "ROSE: bind failed: invalid address\n");
		return -EADDRNOTAVAIL;
	}

	source = &addr->srose_call;

	user = ax25_findbyuid(current_euid());
	if (user) {
		rose->source_call = user->call;
		ax25_uid_put(user);
	} else {
		if (ax25_uid_policy && !capable(CAP_NET_BIND_SERVICE))
			return -EACCES;
		rose->source_call   = *source;
	}

	rose->source_addr   = addr->srose_addr;
	rose->device        = dev;
	rose->source_ndigis = addr->srose_ndigis;

	if (addr_len == sizeof(struct full_sockaddr_rose)) {
		struct full_sockaddr_rose *full_addr = (struct full_sockaddr_rose *)uaddr;
		for (n = 0 ; n < addr->srose_ndigis ; n++)
			rose->source_digis[n] = full_addr->srose_digis[n];
	} else {
		if (rose->source_ndigis == 1) {
			rose->source_digis[0] = addr->srose_digi;
		}
	}

	rose_insert_socket(sk);

	sock_reset_flag(sk, SOCK_ZAPPED);
	SOCK_DEBUG(sk, "ROSE: socket is bound\n");
	return 0;
}
