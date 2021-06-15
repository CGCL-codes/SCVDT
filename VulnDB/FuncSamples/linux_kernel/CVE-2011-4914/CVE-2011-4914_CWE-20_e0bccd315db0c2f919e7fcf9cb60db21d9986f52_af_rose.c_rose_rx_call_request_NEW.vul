int rose_rx_call_request(struct sk_buff *skb, struct net_device *dev, struct rose_neigh *neigh, unsigned int lci)
{
	struct sock *sk;
	struct sock *make;
	struct rose_sock *make_rose;
	struct rose_facilities_struct facilities;
	int n;

	skb->sk = NULL;		/* Initially we don't know who it's for */

	/*
	 *	skb->data points to the rose frame start
	 */
	memset(&facilities, 0x00, sizeof(struct rose_facilities_struct));

	if (!rose_parse_facilities(skb->data + ROSE_CALL_REQ_FACILITIES_OFF,
				   skb->len - ROSE_CALL_REQ_FACILITIES_OFF,
				   &facilities)) {
		rose_transmit_clear_request(neigh, lci, ROSE_INVALID_FACILITY, 76);
		return 0;
	}

	sk = rose_find_listener(&facilities.source_addr, &facilities.source_call);

	/*
	 * We can't accept the Call Request.
	 */
	if (sk == NULL || sk_acceptq_is_full(sk) ||
	    (make = rose_make_new(sk)) == NULL) {
		rose_transmit_clear_request(neigh, lci, ROSE_NETWORK_CONGESTION, 120);
		return 0;
	}

	skb->sk     = make;
	make->sk_state = TCP_ESTABLISHED;
	make_rose = rose_sk(make);

	make_rose->lci           = lci;
	make_rose->dest_addr     = facilities.dest_addr;
	make_rose->dest_call     = facilities.dest_call;
	make_rose->dest_ndigis   = facilities.dest_ndigis;
	for (n = 0 ; n < facilities.dest_ndigis ; n++)
		make_rose->dest_digis[n] = facilities.dest_digis[n];
	make_rose->source_addr   = facilities.source_addr;
	make_rose->source_call   = facilities.source_call;
	make_rose->source_ndigis = facilities.source_ndigis;
	for (n = 0 ; n < facilities.source_ndigis ; n++)
		make_rose->source_digis[n]= facilities.source_digis[n];
	make_rose->neighbour     = neigh;
	make_rose->device        = dev;
	make_rose->facilities    = facilities;

	make_rose->neighbour->use++;

	if (rose_sk(sk)->defer) {
		make_rose->state = ROSE_STATE_5;
	} else {
		rose_write_internal(make, ROSE_CALL_ACCEPTED);
		make_rose->state = ROSE_STATE_3;
		rose_start_idletimer(make);
	}

	make_rose->condition = 0x00;
	make_rose->vs        = 0;
	make_rose->va        = 0;
	make_rose->vr        = 0;
	make_rose->vl        = 0;
	sk->sk_ack_backlog++;

	rose_insert_socket(make);

	skb_queue_head(&sk->sk_receive_queue, skb);

	rose_start_heartbeat(make);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb->len);

	return 1;
}
