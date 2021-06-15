static int xfrm_alloc_replay_state_esn(struct xfrm_replay_state_esn **replay_esn,
				       struct xfrm_replay_state_esn **preplay_esn,
				       struct nlattr *rta)
{
	struct xfrm_replay_state_esn *p, *pp, *up;

	if (!rta)
		return 0;

	up = nla_data(rta);

	p = kmemdup(up, xfrm_replay_state_esn_len(up), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	pp = kmemdup(up, xfrm_replay_state_esn_len(up), GFP_KERNEL);
	if (!pp) {
		kfree(p);
		return -ENOMEM;
	}

	*replay_esn = p;
	*preplay_esn = pp;

	return 0;
}
