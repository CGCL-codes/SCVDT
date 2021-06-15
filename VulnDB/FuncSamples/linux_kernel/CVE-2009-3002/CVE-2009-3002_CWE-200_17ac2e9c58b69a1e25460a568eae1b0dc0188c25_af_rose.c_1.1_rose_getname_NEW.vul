static int rose_getname(struct socket *sock, struct sockaddr *uaddr,
	int *uaddr_len, int peer)
{
	struct full_sockaddr_rose *srose = (struct full_sockaddr_rose *)uaddr;
	struct sock *sk = sock->sk;
	struct rose_sock *rose = rose_sk(sk);
	int n;

	memset(srose, 0, sizeof(*srose));
	if (peer != 0) {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -ENOTCONN;
		srose->srose_family = AF_ROSE;
		srose->srose_addr   = rose->dest_addr;
		srose->srose_call   = rose->dest_call;
		srose->srose_ndigis = rose->dest_ndigis;
		for (n = 0; n < rose->dest_ndigis; n++)
			srose->srose_digis[n] = rose->dest_digis[n];
	} else {
		srose->srose_family = AF_ROSE;
		srose->srose_addr   = rose->source_addr;
		srose->srose_call   = rose->source_call;
		srose->srose_ndigis = rose->source_ndigis;
		for (n = 0; n < rose->source_ndigis; n++)
			srose->srose_digis[n] = rose->source_digis[n];
	}

	*uaddr_len = sizeof(struct full_sockaddr_rose);
	return 0;
}
