void ping_unhash(struct sock *sk)
{
	struct inet_sock *isk = inet_sk(sk);
	pr_debug("ping_unhash(isk=%p,isk->num=%u)\n", isk, isk->inet_num);
	if (sk_hashed(sk)) {
		write_lock_bh(&ping_table.lock);
		hlist_nulls_del(&sk->sk_nulls_node);
		sock_put(sk);
		isk->inet_num = 0;
		isk->inet_sport = 0;
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
		write_unlock_bh(&ping_table.lock);
	}
}
