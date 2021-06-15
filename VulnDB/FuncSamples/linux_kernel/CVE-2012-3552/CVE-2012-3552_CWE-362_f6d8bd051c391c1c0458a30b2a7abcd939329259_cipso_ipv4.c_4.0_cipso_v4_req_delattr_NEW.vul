void cipso_v4_req_delattr(struct request_sock *req)
{
	struct ip_options_rcu *opt;
	struct inet_request_sock *req_inet;

	req_inet = inet_rsk(req);
	opt = req_inet->opt;
	if (opt == NULL || opt->opt.cipso == 0)
		return;

	cipso_v4_delopt(&req_inet->opt);
}
