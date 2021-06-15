static int rds_recv_track_latency(struct rds_sock *rs, char __user *optval,
				  int optlen)
{
	struct rds_rx_trace_so trace;
	int i;

	if (optlen != sizeof(struct rds_rx_trace_so))
		return -EFAULT;

	if (copy_from_user(&trace, optval, sizeof(trace)))
		return -EFAULT;

	if (trace.rx_traces > RDS_MSG_RX_DGRAM_TRACE_MAX)
		return -EFAULT;

	rs->rs_rx_traces = trace.rx_traces;
	for (i = 0; i < rs->rs_rx_traces; i++) {
		if (trace.rx_trace_pos[i] > RDS_MSG_RX_DGRAM_TRACE_MAX) {
			rs->rs_rx_traces = 0;
			return -EFAULT;
		}
		rs->rs_rx_trace[i] = trace.rx_trace_pos[i];
	}

	return 0;
}
