static ieee80211_tx_result
ieee80211_tx_h_unicast_ps_buf(struct ieee80211_tx_data *tx)
{
	struct sta_info *sta = tx->sta;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
	struct ieee80211_local *local = tx->local;

	if (unlikely(!sta))
		return TX_CONTINUE;

	if (unlikely((test_sta_flag(sta, WLAN_STA_PS_STA) ||
		      test_sta_flag(sta, WLAN_STA_PS_DRIVER)) &&
		     !(info->flags & IEEE80211_TX_CTL_NO_PS_BUFFER))) {
		int ac = skb_get_queue_mapping(tx->skb);

		ps_dbg(sta->sdata, "STA %pM aid %d: PS buffer for AC %d\n",
		       sta->sta.addr, sta->sta.aid, ac);
		if (tx->local->total_ps_buffered >= TOTAL_MAX_TX_BUFFER)
			purge_old_ps_buffers(tx->local);

		/* sync with ieee80211_sta_ps_deliver_wakeup */
		spin_lock(&sta->ps_lock);
		/*
		 * STA woke up the meantime and all the frames on ps_tx_buf have
		 * been queued to pending queue. No reordering can happen, go
		 * ahead and Tx the packet.
		 */
		if (!test_sta_flag(sta, WLAN_STA_PS_STA) &&
		    !test_sta_flag(sta, WLAN_STA_PS_DRIVER)) {
			spin_unlock(&sta->ps_lock);
			return TX_CONTINUE;
		}

		if (skb_queue_len(&sta->ps_tx_buf[ac]) >= STA_MAX_TX_BUFFER) {
			struct sk_buff *old = skb_dequeue(&sta->ps_tx_buf[ac]);
			ps_dbg(tx->sdata,
			       "STA %pM TX buffer for AC %d full - dropping oldest frame\n",
			       sta->sta.addr, ac);
			ieee80211_free_txskb(&local->hw, old);
		} else
			tx->local->total_ps_buffered++;

		info->control.jiffies = jiffies;
		info->control.vif = &tx->sdata->vif;
		info->flags |= IEEE80211_TX_INTFL_NEED_TXPROCESSING;
		info->flags &= ~IEEE80211_TX_TEMPORARY_FLAGS;
		skb_queue_tail(&sta->ps_tx_buf[ac], tx->skb);
		spin_unlock(&sta->ps_lock);

		if (!timer_pending(&local->sta_cleanup))
			mod_timer(&local->sta_cleanup,
				  round_jiffies(jiffies +
						STA_INFO_CLEANUP_INTERVAL));

		/*
		 * We queued up some frames, so the TIM bit might
		 * need to be set, recalculate it.
		 */
		sta_info_recalc_tim(sta);

		return TX_QUEUED;
	} else if (unlikely(test_sta_flag(sta, WLAN_STA_PS_STA))) {
		ps_dbg(tx->sdata,
		       "STA %pM in PS mode, but polling/in SP -> send frame\n",
		       sta->sta.addr);
	}

	return TX_CONTINUE;
}
