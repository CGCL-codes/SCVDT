int cipso_v4_sock_getattr(struct sock *sk, struct netlbl_lsm_secattr *secattr)
{
	struct ip_options_rcu *opt;
	int res = -ENOMSG;

	rcu_read_lock();
	opt = rcu_dereference(inet_sk(sk)->inet_opt);
	if (opt && opt->opt.cipso)
		res = cipso_v4_getattr(opt->opt.__data +
						opt->opt.cipso -
						sizeof(struct iphdr),
				       secattr);
	rcu_read_unlock();
	return res;
}
