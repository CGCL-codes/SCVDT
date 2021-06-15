struct ipv6_txoptions *
ipv6_dup_options(struct sock *sk, struct ipv6_txoptions *opt)
{
	struct ipv6_txoptions *opt2;

	opt2 = sock_kmalloc(sk, opt->tot_len, GFP_ATOMIC);
	if (opt2) {
		long dif = (char *)opt2 - (char *)opt;
		memcpy(opt2, opt, opt->tot_len);
		if (opt2->hopopt)
			*((char **)&opt2->hopopt) += dif;
		if (opt2->dst0opt)
			*((char **)&opt2->dst0opt) += dif;
		if (opt2->dst1opt)
			*((char **)&opt2->dst1opt) += dif;
		if (opt2->srcrt)
			*((char **)&opt2->srcrt) += dif;
		atomic_set(&opt2->refcnt, 1);
	}
	return opt2;
}
