static int rfcomm_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct rfcomm_dlc *d = rfcomm_pi(sk)->dlc;
	int len;

	if (test_and_clear_bit(RFCOMM_DEFER_SETUP, &d->flags)) {
		rfcomm_dlc_accept(d);
		return 0;
	}

	len = bt_sock_stream_recvmsg(iocb, sock, msg, size, flags);

	lock_sock(sk);
	if (!(flags & MSG_PEEK) && len > 0)
		atomic_sub(len, &sk->sk_rmem_alloc);

	if (atomic_read(&sk->sk_rmem_alloc) <= (sk->sk_rcvbuf >> 2))
		rfcomm_dlc_unthrottle(rfcomm_pi(sk)->dlc);
	release_sock(sk);

	return len;
}
