static inline int xfrm_replay_verify_len(struct xfrm_replay_state_esn *replay_esn,
					 struct nlattr *rp)
{
	struct xfrm_replay_state_esn *up;

	if (!replay_esn || !rp)
		return 0;

	up = nla_data(rp);

	if (xfrm_replay_state_esn_len(replay_esn) !=
			xfrm_replay_state_esn_len(up))
		return -EINVAL;

	return 0;
}
