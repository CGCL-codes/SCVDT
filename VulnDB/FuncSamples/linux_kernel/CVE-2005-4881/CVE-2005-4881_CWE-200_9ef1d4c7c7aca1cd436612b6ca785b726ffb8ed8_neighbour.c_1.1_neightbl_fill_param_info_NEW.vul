static int neightbl_fill_param_info(struct neigh_table *tbl,
				    struct neigh_parms *parms,
				    struct sk_buff *skb,
				    struct netlink_callback *cb)
{
	struct ndtmsg *ndtmsg;
	struct nlmsghdr *nlh;

	nlh = NLMSG_NEW_ANSWER(skb, cb, RTM_NEWNEIGHTBL, sizeof(struct ndtmsg),
			       NLM_F_MULTI);

	ndtmsg = NLMSG_DATA(nlh);

	read_lock_bh(&tbl->lock);
	ndtmsg->ndtm_family = tbl->family;
	ndtmsg->ndtm_pad1   = 0;
	ndtmsg->ndtm_pad2   = 0;
	RTA_PUT_STRING(skb, NDTA_NAME, tbl->id);

	if (neightbl_fill_parms(skb, parms) < 0)
		goto rtattr_failure;

	read_unlock_bh(&tbl->lock);
	return NLMSG_END(skb, nlh);

rtattr_failure:
	read_unlock_bh(&tbl->lock);
	return NLMSG_CANCEL(skb, nlh);

nlmsg_failure:
	return -1;
}
