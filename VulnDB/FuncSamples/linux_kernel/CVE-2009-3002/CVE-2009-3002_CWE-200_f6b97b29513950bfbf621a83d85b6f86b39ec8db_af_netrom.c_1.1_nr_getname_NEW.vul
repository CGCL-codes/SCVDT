static int nr_getname(struct socket *sock, struct sockaddr *uaddr,
	int *uaddr_len, int peer)
{
	struct full_sockaddr_ax25 *sax = (struct full_sockaddr_ax25 *)uaddr;
	struct sock *sk = sock->sk;
	struct nr_sock *nr = nr_sk(sk);

	lock_sock(sk);
	if (peer != 0) {
		if (sk->sk_state != TCP_ESTABLISHED) {
			release_sock(sk);
			return -ENOTCONN;
		}
		sax->fsa_ax25.sax25_family = AF_NETROM;
		sax->fsa_ax25.sax25_ndigis = 1;
		sax->fsa_ax25.sax25_call   = nr->user_addr;
		memset(sax->fsa_digipeater, 0, sizeof(sax->fsa_digipeater));
		sax->fsa_digipeater[0]     = nr->dest_addr;
		*uaddr_len = sizeof(struct full_sockaddr_ax25);
	} else {
		sax->fsa_ax25.sax25_family = AF_NETROM;
		sax->fsa_ax25.sax25_ndigis = 0;
		sax->fsa_ax25.sax25_call   = nr->source_addr;
		*uaddr_len = sizeof(struct sockaddr_ax25);
	}
	release_sock(sk);

	return 0;
}
