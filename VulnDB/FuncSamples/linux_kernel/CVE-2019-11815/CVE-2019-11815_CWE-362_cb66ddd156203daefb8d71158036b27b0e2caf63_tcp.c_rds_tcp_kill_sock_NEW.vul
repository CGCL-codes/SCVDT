static void rds_tcp_kill_sock(struct net *net)
{
	struct rds_tcp_connection *tc, *_tc;
	LIST_HEAD(tmp_list);
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);
	struct socket *lsock = rtn->rds_tcp_listen_sock;

	rtn->rds_tcp_listen_sock = NULL;
	rds_tcp_listen_stop(lsock, &rtn->rds_tcp_accept_w);
	spin_lock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &rds_tcp_conn_list, t_tcp_node) {
		struct net *c_net = read_pnet(&tc->t_cpath->cp_conn->c_net);

		if (net != c_net)
			continue;
		if (!list_has_conn(&tmp_list, tc->t_cpath->cp_conn)) {
			list_move_tail(&tc->t_tcp_node, &tmp_list);
		} else {
			list_del(&tc->t_tcp_node);
			tc->t_tcp_node_detached = true;
		}
	}
	spin_unlock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &tmp_list, t_tcp_node)
		rds_conn_destroy(tc->t_cpath->cp_conn);
}
