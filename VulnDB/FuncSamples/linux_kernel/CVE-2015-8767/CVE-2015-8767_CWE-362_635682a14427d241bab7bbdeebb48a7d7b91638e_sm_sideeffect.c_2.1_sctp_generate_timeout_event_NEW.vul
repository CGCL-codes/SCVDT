static void sctp_generate_timeout_event(struct sctp_association *asoc,
					sctp_event_timeout_t timeout_type)
{
	struct sock *sk = asoc->base.sk;
	struct net *net = sock_net(sk);
	int error = 0;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		pr_debug("%s: sock is busy: timer %d\n", __func__,
			 timeout_type);

		/* Try again later.  */
		if (!mod_timer(&asoc->timers[timeout_type], jiffies + (HZ/20)))
			sctp_association_hold(asoc);
		goto out_unlock;
	}

	/* Is this association really dead and just waiting around for
	 * the timer to let go of the reference?
	 */
	if (asoc->base.dead)
		goto out_unlock;

	/* Run through the state machine.  */
	error = sctp_do_sm(net, SCTP_EVENT_T_TIMEOUT,
			   SCTP_ST_TIMEOUT(timeout_type),
			   asoc->state, asoc->ep, asoc,
			   (void *)timeout_type, GFP_ATOMIC);

	if (error)
		sk->sk_err = -error;

out_unlock:
	bh_unlock_sock(sk);
	sctp_association_put(asoc);
}
