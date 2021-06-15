static void fanout_release(struct sock *sk)
{
	struct packet_sock *po = pkt_sk(sk);
	struct packet_fanout *f;

	f = po->fanout;
	if (!f)
		return;

	mutex_lock(&fanout_mutex);
	po->fanout = NULL;

	if (atomic_dec_and_test(&f->sk_ref)) {
		list_del(&f->list);
		dev_remove_pack(&f->prot_hook);
		fanout_release_data(f);
		kfree(f);
	}
	mutex_unlock(&fanout_mutex);

	if (po->rollover)
		kfree_rcu(po->rollover, rcu);
}
