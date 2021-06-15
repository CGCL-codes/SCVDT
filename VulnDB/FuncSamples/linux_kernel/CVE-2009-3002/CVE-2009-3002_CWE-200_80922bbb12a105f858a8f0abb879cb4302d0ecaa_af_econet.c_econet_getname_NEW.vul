static int econet_getname(struct socket *sock, struct sockaddr *uaddr,
			  int *uaddr_len, int peer)
{
	struct sock *sk;
	struct econet_sock *eo;
	struct sockaddr_ec *sec = (struct sockaddr_ec *)uaddr;

	if (peer)
		return -EOPNOTSUPP;

	memset(sec, 0, sizeof(*sec));
	mutex_lock(&econet_mutex);

	sk = sock->sk;
	eo = ec_sk(sk);

	sec->sec_family	  = AF_ECONET;
	sec->port	  = eo->port;
	sec->addr.station = eo->station;
	sec->addr.net	  = eo->net;

	mutex_unlock(&econet_mutex);

	*uaddr_len = sizeof(*sec);
	return 0;
}
