static inline int verify_replay(struct xfrm_usersa_info *p,
				struct nlattr **attrs)
{
	struct nlattr *rt = attrs[XFRMA_REPLAY_ESN_VAL];

	if ((p->flags & XFRM_STATE_ESN) && !rt)
		return -EINVAL;

	if (!rt)
		return 0;

	if (p->id.proto != IPPROTO_ESP)
		return -EINVAL;

	if (p->replay_window != 0)
		return -EINVAL;

	return 0;
}
