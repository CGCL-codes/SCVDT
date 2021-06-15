int ___ieee80211_stop_tx_ba_session(struct sta_info *sta, u16 tid,
				    enum ieee80211_back_parties initiator)
{
	struct ieee80211_local *local = sta->local;
	int ret;
	u8 *state;

#ifdef CONFIG_MAC80211_HT_DEBUG
	printk(KERN_DEBUG "Tx BA session stop requested for %pM tid %u\n",
	       sta->sta.addr, tid);
#endif /* CONFIG_MAC80211_HT_DEBUG */

	state = &sta->ampdu_mlme.tid_state_tx[tid];

	if (*state == HT_AGG_STATE_OPERATIONAL)
		sta->ampdu_mlme.addba_req_num[tid] = 0;

	*state = HT_AGG_STATE_REQ_STOP_BA_MSK |
		(initiator << HT_AGG_STATE_INITIATOR_SHIFT);

	ret = drv_ampdu_action(local, IEEE80211_AMPDU_TX_STOP,
			       &sta->sta, tid, NULL);

	/* HW shall not deny going back to legacy */
	if (WARN_ON(ret)) {
		/*
		 * We may have pending packets get stuck in this case...
		 * Not bothering with a workaround for now.
		 */
	}

	return ret;
}
