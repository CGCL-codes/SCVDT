static int rfcomm_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_rc *sa = (struct sockaddr_rc *) addr;
	struct sock *sk = sock->sk;
	int chan = sa->rc_channel;
	int err = 0;

	BT_DBG("sk %p %pMR", sk, &sa->rc_bdaddr);

	if (!addr || addr->sa_family != AF_BLUETOOTH)
		return -EINVAL;

	lock_sock(sk);

	if (sk->sk_state != BT_OPEN) {
		err = -EBADFD;
		goto done;
	}

	if (sk->sk_type != SOCK_STREAM) {
		err = -EINVAL;
		goto done;
	}

	write_lock(&rfcomm_sk_list.lock);

	if (chan && __rfcomm_get_listen_sock_by_addr(chan, &sa->rc_bdaddr)) {
		err = -EADDRINUSE;
	} else {
		/* Save source address */
		bacpy(&rfcomm_pi(sk)->src, &sa->rc_bdaddr);
		rfcomm_pi(sk)->channel = chan;
		sk->sk_state = BT_BOUND;
	}

	write_unlock(&rfcomm_sk_list.lock);

done:
	release_sock(sk);
	return err;
}
