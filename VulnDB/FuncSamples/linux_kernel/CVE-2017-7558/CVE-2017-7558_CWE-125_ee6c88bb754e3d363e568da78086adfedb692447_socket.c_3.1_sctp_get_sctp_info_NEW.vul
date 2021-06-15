int sctp_get_sctp_info(struct sock *sk, struct sctp_association *asoc,
		       struct sctp_info *info)
{
	struct sctp_transport *prim;
	struct list_head *pos;
	int mask;

	memset(info, 0, sizeof(*info));
	if (!asoc) {
		struct sctp_sock *sp = sctp_sk(sk);

		info->sctpi_s_autoclose = sp->autoclose;
		info->sctpi_s_adaptation_ind = sp->adaptation_ind;
		info->sctpi_s_pd_point = sp->pd_point;
		info->sctpi_s_nodelay = sp->nodelay;
		info->sctpi_s_disable_fragments = sp->disable_fragments;
		info->sctpi_s_v4mapped = sp->v4mapped;
		info->sctpi_s_frag_interleave = sp->frag_interleave;
		info->sctpi_s_type = sp->type;

		return 0;
	}

	info->sctpi_tag = asoc->c.my_vtag;
	info->sctpi_state = asoc->state;
	info->sctpi_rwnd = asoc->a_rwnd;
	info->sctpi_unackdata = asoc->unack_data;
	info->sctpi_penddata = sctp_tsnmap_pending(&asoc->peer.tsn_map);
	info->sctpi_instrms = asoc->stream.incnt;
	info->sctpi_outstrms = asoc->stream.outcnt;
	list_for_each(pos, &asoc->base.inqueue.in_chunk_list)
		info->sctpi_inqueue++;
	list_for_each(pos, &asoc->outqueue.out_chunk_list)
		info->sctpi_outqueue++;
	info->sctpi_overall_error = asoc->overall_error_count;
	info->sctpi_max_burst = asoc->max_burst;
	info->sctpi_maxseg = asoc->frag_point;
	info->sctpi_peer_rwnd = asoc->peer.rwnd;
	info->sctpi_peer_tag = asoc->c.peer_vtag;

	mask = asoc->peer.ecn_capable << 1;
	mask = (mask | asoc->peer.ipv4_address) << 1;
	mask = (mask | asoc->peer.ipv6_address) << 1;
	mask = (mask | asoc->peer.hostname_address) << 1;
	mask = (mask | asoc->peer.asconf_capable) << 1;
	mask = (mask | asoc->peer.prsctp_capable) << 1;
	mask = (mask | asoc->peer.auth_capable);
	info->sctpi_peer_capable = mask;
	mask = asoc->peer.sack_needed << 1;
	mask = (mask | asoc->peer.sack_generation) << 1;
	mask = (mask | asoc->peer.zero_window_announced);
	info->sctpi_peer_sack = mask;

	info->sctpi_isacks = asoc->stats.isacks;
	info->sctpi_osacks = asoc->stats.osacks;
	info->sctpi_opackets = asoc->stats.opackets;
	info->sctpi_ipackets = asoc->stats.ipackets;
	info->sctpi_rtxchunks = asoc->stats.rtxchunks;
	info->sctpi_outofseqtsns = asoc->stats.outofseqtsns;
	info->sctpi_idupchunks = asoc->stats.idupchunks;
	info->sctpi_gapcnt = asoc->stats.gapcnt;
	info->sctpi_ouodchunks = asoc->stats.ouodchunks;
	info->sctpi_iuodchunks = asoc->stats.iuodchunks;
	info->sctpi_oodchunks = asoc->stats.oodchunks;
	info->sctpi_iodchunks = asoc->stats.iodchunks;
	info->sctpi_octrlchunks = asoc->stats.octrlchunks;
	info->sctpi_ictrlchunks = asoc->stats.ictrlchunks;

	prim = asoc->peer.primary_path;
	memcpy(&info->sctpi_p_address, &prim->ipaddr, sizeof(prim->ipaddr));
	info->sctpi_p_state = prim->state;
	info->sctpi_p_cwnd = prim->cwnd;
	info->sctpi_p_srtt = prim->srtt;
	info->sctpi_p_rto = jiffies_to_msecs(prim->rto);
	info->sctpi_p_hbinterval = prim->hbinterval;
	info->sctpi_p_pathmaxrxt = prim->pathmaxrxt;
	info->sctpi_p_sackdelay = jiffies_to_msecs(prim->sackdelay);
	info->sctpi_p_ssthresh = prim->ssthresh;
	info->sctpi_p_partial_bytes_acked = prim->partial_bytes_acked;
	info->sctpi_p_flight_size = prim->flight_size;
	info->sctpi_p_error = prim->error_count;

	return 0;
}
