static int xfrm_dump_policy_done(struct netlink_callback *cb)
{
	struct xfrm_policy_walk *walk = (struct xfrm_policy_walk *) &cb->args[1];
	struct net *net = sock_net(cb->skb->sk);

	xfrm_policy_walk_done(walk, net);
	return 0;
}
