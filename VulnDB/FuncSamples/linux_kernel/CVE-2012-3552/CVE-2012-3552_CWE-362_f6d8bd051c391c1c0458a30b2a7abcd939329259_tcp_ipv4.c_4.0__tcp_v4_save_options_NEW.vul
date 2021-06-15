static struct ip_options_rcu *tcp_v4_save_options(struct sock *sk,
						  struct sk_buff *skb)
{
	const struct ip_options *opt = &(IPCB(skb)->opt);
	struct ip_options_rcu *dopt = NULL;

	if (opt && opt->optlen) {
		int opt_size = sizeof(*dopt) + opt->optlen;

		dopt = kmalloc(opt_size, GFP_ATOMIC);
		if (dopt) {
			if (ip_options_echo(&dopt->opt, skb)) {
				kfree(dopt);
				dopt = NULL;
			}
		}
	}
	return dopt;
}
