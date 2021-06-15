static int unix_dgram_connect(struct socket *sock, struct sockaddr *addr,
			      int alen, int flags)
{
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);
	struct sockaddr_un *sunaddr = (struct sockaddr_un *)addr;
	struct sock *other;
	unsigned int hash;
	int err;

	if (addr->sa_family != AF_UNSPEC) {
		err = unix_mkname(sunaddr, alen, &hash);
		if (err < 0)
			goto out;
		alen = err;

		if (test_bit(SOCK_PASSCRED, &sock->flags) &&
		    !unix_sk(sk)->addr && (err = unix_autobind(sock)) != 0)
			goto out;

restart:
		other = unix_find_other(net, sunaddr, alen, sock->type, hash, &err);
		if (!other)
			goto out;

		unix_state_double_lock(sk, other);

		/* Apparently VFS overslept socket death. Retry. */
		if (sock_flag(other, SOCK_DEAD)) {
			unix_state_double_unlock(sk, other);
			sock_put(other);
			goto restart;
		}

		err = -EPERM;
		if (!unix_may_send(sk, other))
			goto out_unlock;

		err = security_unix_may_send(sk->sk_socket, other->sk_socket);
		if (err)
			goto out_unlock;

	} else {
		/*
		 *	1003.1g breaking connected state with AF_UNSPEC
		 */
		other = NULL;
		unix_state_double_lock(sk, other);
	}

	/*
	 * If it was connected, reconnect.
	 */
	if (unix_peer(sk)) {
		struct sock *old_peer = unix_peer(sk);
		unix_peer(sk) = other;
		unix_state_double_unlock(sk, other);

		if (other != old_peer)
			unix_dgram_disconnected(sk, old_peer);
		sock_put(old_peer);
	} else {
		unix_peer(sk) = other;
		unix_state_double_unlock(sk, other);
	}
	return 0;

out_unlock:
	unix_state_double_unlock(sk, other);
	sock_put(other);
out:
	return err;
}
