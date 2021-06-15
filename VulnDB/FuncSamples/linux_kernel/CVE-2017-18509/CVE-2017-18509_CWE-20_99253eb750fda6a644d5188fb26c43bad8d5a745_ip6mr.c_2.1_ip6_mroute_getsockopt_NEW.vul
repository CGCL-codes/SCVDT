int ip6_mroute_getsockopt(struct sock *sk, int optname, char __user *optval,
			  int __user *optlen)
{
	int olr;
	int val;
	struct net *net = sock_net(sk);
	struct mr6_table *mrt;

	if (sk->sk_type != SOCK_RAW ||
	    inet_sk(sk)->inet_num != IPPROTO_ICMPV6)
		return -EOPNOTSUPP;

	mrt = ip6mr_get_table(net, raw6_sk(sk)->ip6mr_table ? : RT6_TABLE_DFLT);
	if (!mrt)
		return -ENOENT;

	switch (optname) {
	case MRT6_VERSION:
		val = 0x0305;
		break;
#ifdef CONFIG_IPV6_PIMSM_V2
	case MRT6_PIM:
		val = mrt->mroute_do_pim;
		break;
#endif
	case MRT6_ASSERT:
		val = mrt->mroute_do_assert;
		break;
	default:
		return -ENOPROTOOPT;
	}

	if (get_user(olr, optlen))
		return -EFAULT;

	olr = min_t(int, olr, sizeof(int));
	if (olr < 0)
		return -EINVAL;

	if (put_user(olr, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, olr))
		return -EFAULT;
	return 0;
}
