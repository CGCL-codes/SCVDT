static int xfrm_alloc_replay_state_esn(struct xfrm_replay_state_esn **replay_esn,
				       struct xfrm_replay_state_esn **preplay_esn,
				       struct nlattr *rta)
{
	struct xfrm_replay_state_esn *p, *pp, *up;
	int klen, ulen;

	if (!rta)
		return 0;

	up = nla_data(rta);
	klen = xfrm_replay_state_esn_len(up);
	ulen = nla_len(rta) >= klen ? klen : sizeof(*up);

	p = kzalloc(klen, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	pp = kzalloc(klen, GFP_KERNEL);
	if (!pp) {
		kfree(p);
		return -ENOMEM;
	}

	memcpy(p, up, ulen);
	memcpy(pp, up, ulen);

	*replay_esn = p;
	*preplay_esn = pp;

	return 0;
}
