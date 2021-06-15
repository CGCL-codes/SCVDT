int sock_getsockopt(struct socket *sock, int level, int optname,
		    char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;

	union {
		int val;
		struct linger ling;
		struct timeval tm;
	} v;

	int lv = sizeof(int);
	int len;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	memset(&v, 0, sizeof(v));

	switch (optname) {
	case SO_DEBUG:
		v.val = sock_flag(sk, SOCK_DBG);
		break;

	case SO_DONTROUTE:
		v.val = sock_flag(sk, SOCK_LOCALROUTE);
		break;

	case SO_BROADCAST:
		v.val = !!sock_flag(sk, SOCK_BROADCAST);
		break;

	case SO_SNDBUF:
		v.val = sk->sk_sndbuf;
		break;

	case SO_RCVBUF:
		v.val = sk->sk_rcvbuf;
		break;

	case SO_REUSEADDR:
		v.val = sk->sk_reuse;
		break;

	case SO_KEEPALIVE:
		v.val = !!sock_flag(sk, SOCK_KEEPOPEN);
		break;

	case SO_TYPE:
		v.val = sk->sk_type;
		break;

	case SO_PROTOCOL:
		v.val = sk->sk_protocol;
		break;

	case SO_DOMAIN:
		v.val = sk->sk_family;
		break;

	case SO_ERROR:
		v.val = -sock_error(sk);
		if (v.val == 0)
			v.val = xchg(&sk->sk_err_soft, 0);
		break;

	case SO_OOBINLINE:
		v.val = !!sock_flag(sk, SOCK_URGINLINE);
		break;

	case SO_NO_CHECK:
		v.val = sk->sk_no_check;
		break;

	case SO_PRIORITY:
		v.val = sk->sk_priority;
		break;

	case SO_LINGER:
		lv		= sizeof(v.ling);
		v.ling.l_onoff	= !!sock_flag(sk, SOCK_LINGER);
		v.ling.l_linger	= sk->sk_lingertime / HZ;
		break;

	case SO_BSDCOMPAT:
		sock_warn_obsolete_bsdism("getsockopt");
		break;

	case SO_TIMESTAMP:
		v.val = sock_flag(sk, SOCK_RCVTSTAMP) &&
				!sock_flag(sk, SOCK_RCVTSTAMPNS);
		break;

	case SO_TIMESTAMPNS:
		v.val = sock_flag(sk, SOCK_RCVTSTAMPNS);
		break;

	case SO_TIMESTAMPING:
		v.val = 0;
		if (sock_flag(sk, SOCK_TIMESTAMPING_TX_HARDWARE))
			v.val |= SOF_TIMESTAMPING_TX_HARDWARE;
		if (sock_flag(sk, SOCK_TIMESTAMPING_TX_SOFTWARE))
			v.val |= SOF_TIMESTAMPING_TX_SOFTWARE;
		if (sock_flag(sk, SOCK_TIMESTAMPING_RX_HARDWARE))
			v.val |= SOF_TIMESTAMPING_RX_HARDWARE;
		if (sock_flag(sk, SOCK_TIMESTAMPING_RX_SOFTWARE))
			v.val |= SOF_TIMESTAMPING_RX_SOFTWARE;
		if (sock_flag(sk, SOCK_TIMESTAMPING_SOFTWARE))
			v.val |= SOF_TIMESTAMPING_SOFTWARE;
		if (sock_flag(sk, SOCK_TIMESTAMPING_SYS_HARDWARE))
			v.val |= SOF_TIMESTAMPING_SYS_HARDWARE;
		if (sock_flag(sk, SOCK_TIMESTAMPING_RAW_HARDWARE))
			v.val |= SOF_TIMESTAMPING_RAW_HARDWARE;
		break;

	case SO_RCVTIMEO:
		lv = sizeof(struct timeval);
		if (sk->sk_rcvtimeo == MAX_SCHEDULE_TIMEOUT) {
			v.tm.tv_sec = 0;
			v.tm.tv_usec = 0;
		} else {
			v.tm.tv_sec = sk->sk_rcvtimeo / HZ;
			v.tm.tv_usec = ((sk->sk_rcvtimeo % HZ) * 1000000) / HZ;
		}
		break;

	case SO_SNDTIMEO:
		lv = sizeof(struct timeval);
		if (sk->sk_sndtimeo == MAX_SCHEDULE_TIMEOUT) {
			v.tm.tv_sec = 0;
			v.tm.tv_usec = 0;
		} else {
			v.tm.tv_sec = sk->sk_sndtimeo / HZ;
			v.tm.tv_usec = ((sk->sk_sndtimeo % HZ) * 1000000) / HZ;
		}
		break;

	case SO_RCVLOWAT:
		v.val = sk->sk_rcvlowat;
		break;

	case SO_SNDLOWAT:
		v.val = 1;
		break;

	case SO_PASSCRED:
		v.val = !!test_bit(SOCK_PASSCRED, &sock->flags);
		break;

	case SO_PEERCRED:
	{
		struct ucred peercred;
		if (len > sizeof(peercred))
			len = sizeof(peercred);
		cred_to_ucred(sk->sk_peer_pid, sk->sk_peer_cred, &peercred);
		if (copy_to_user(optval, &peercred, len))
			return -EFAULT;
		goto lenout;
	}

	case SO_PEERNAME:
	{
		char address[128];

		if (sock->ops->getname(sock, (struct sockaddr *)address, &lv, 2))
			return -ENOTCONN;
		if (lv < len)
			return -EINVAL;
		if (copy_to_user(optval, address, len))
			return -EFAULT;
		goto lenout;
	}

	/* Dubious BSD thing... Probably nobody even uses it, but
	 * the UNIX standard wants it for whatever reason... -DaveM
	 */
	case SO_ACCEPTCONN:
		v.val = sk->sk_state == TCP_LISTEN;
		break;

	case SO_PASSSEC:
		v.val = !!test_bit(SOCK_PASSSEC, &sock->flags);
		break;

	case SO_PEERSEC:
		return security_socket_getpeersec_stream(sock, optval, optlen, len);

	case SO_MARK:
		v.val = sk->sk_mark;
		break;

	case SO_RXQ_OVFL:
		v.val = !!sock_flag(sk, SOCK_RXQ_OVFL);
		break;

	case SO_WIFI_STATUS:
		v.val = !!sock_flag(sk, SOCK_WIFI_STATUS);
		break;

	case SO_PEEK_OFF:
		if (!sock->ops->set_peek_off)
			return -EOPNOTSUPP;

		v.val = sk->sk_peek_off;
		break;
	case SO_NOFCS:
		v.val = !!sock_flag(sk, SOCK_NOFCS);
		break;
	default:
		return -ENOPROTOOPT;
	}

	if (len > lv)
		len = lv;
	if (copy_to_user(optval, &v, len))
		return -EFAULT;
lenout:
	if (put_user(len, optlen))
		return -EFAULT;
	return 0;
}
