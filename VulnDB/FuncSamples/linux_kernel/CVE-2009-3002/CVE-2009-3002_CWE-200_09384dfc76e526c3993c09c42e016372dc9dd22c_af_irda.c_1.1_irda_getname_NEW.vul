static int irda_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	struct sockaddr_irda saddr;
	struct sock *sk = sock->sk;
	struct irda_sock *self = irda_sk(sk);

	memset(&saddr, 0, sizeof(saddr));
	if (peer) {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -ENOTCONN;

		saddr.sir_family = AF_IRDA;
		saddr.sir_lsap_sel = self->dtsap_sel;
		saddr.sir_addr = self->daddr;
	} else {
		saddr.sir_family = AF_IRDA;
		saddr.sir_lsap_sel = self->stsap_sel;
		saddr.sir_addr = self->saddr;
	}

	IRDA_DEBUG(1, "%s(), tsap_sel = %#x\n", __func__, saddr.sir_lsap_sel);
	IRDA_DEBUG(1, "%s(), addr = %08x\n", __func__, saddr.sir_addr);

	/* uaddr_len come to us uninitialised */
	*uaddr_len = sizeof (struct sockaddr_irda);
	memcpy(uaddr, &saddr, *uaddr_len);

	return 0;
}
