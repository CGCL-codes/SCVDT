static int raw_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *len, int peer)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct raw_sock *ro = raw_sk(sk);

	if (peer)
		return -EOPNOTSUPP;

	addr->can_family  = AF_CAN;
	addr->can_ifindex = ro->ifindex;

	*len = sizeof(*addr);

	return 0;
}
