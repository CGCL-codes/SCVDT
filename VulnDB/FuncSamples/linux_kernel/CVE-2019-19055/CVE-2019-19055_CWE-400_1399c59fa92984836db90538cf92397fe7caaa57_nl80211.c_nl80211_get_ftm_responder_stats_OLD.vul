static int nl80211_get_ftm_responder_stats(struct sk_buff *skb,
					   struct genl_info *info)
{
	struct cfg80211_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cfg80211_ftm_responder_stats ftm_stats = {};
	struct sk_buff *msg;
	void *hdr;
	struct nlattr *ftm_stats_attr;
	int err;

	if (wdev->iftype != NL80211_IFTYPE_AP || !wdev->beacon_interval)
		return -EOPNOTSUPP;

	err = rdev_get_ftm_responder_stats(rdev, dev, &ftm_stats);
	if (err)
		return err;

	if (!ftm_stats.filled)
		return -ENODATA;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = nl80211hdr_put(msg, info->snd_portid, info->snd_seq, 0,
			     NL80211_CMD_GET_FTM_RESPONDER_STATS);
	if (!hdr)
		return -ENOBUFS;

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex))
		goto nla_put_failure;

	ftm_stats_attr = nla_nest_start_noflag(msg,
					       NL80211_ATTR_FTM_RESPONDER_STATS);
	if (!ftm_stats_attr)
		goto nla_put_failure;

#define SET_FTM(field, name, type)					 \
	do { if ((ftm_stats.filled & BIT(NL80211_FTM_STATS_ ## name)) && \
	    nla_put_ ## type(msg, NL80211_FTM_STATS_ ## name,		 \
			     ftm_stats.field))				 \
		goto nla_put_failure; } while (0)
#define SET_FTM_U64(field, name)					 \
	do { if ((ftm_stats.filled & BIT(NL80211_FTM_STATS_ ## name)) && \
	    nla_put_u64_64bit(msg, NL80211_FTM_STATS_ ## name,		 \
			      ftm_stats.field, NL80211_FTM_STATS_PAD))	 \
		goto nla_put_failure; } while (0)

	SET_FTM(success_num, SUCCESS_NUM, u32);
	SET_FTM(partial_num, PARTIAL_NUM, u32);
	SET_FTM(failed_num, FAILED_NUM, u32);
	SET_FTM(asap_num, ASAP_NUM, u32);
	SET_FTM(non_asap_num, NON_ASAP_NUM, u32);
	SET_FTM_U64(total_duration_ms, TOTAL_DURATION_MSEC);
	SET_FTM(unknown_triggers_num, UNKNOWN_TRIGGERS_NUM, u32);
	SET_FTM(reschedule_requests_num, RESCHEDULE_REQUESTS_NUM, u32);
	SET_FTM(out_of_window_triggers_num, OUT_OF_WINDOW_TRIGGERS_NUM, u32);
#undef SET_FTM

	nla_nest_end(msg, ftm_stats_attr);

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}
