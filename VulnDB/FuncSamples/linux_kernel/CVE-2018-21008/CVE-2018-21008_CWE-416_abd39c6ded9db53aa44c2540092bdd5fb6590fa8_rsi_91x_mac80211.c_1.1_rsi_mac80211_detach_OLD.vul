void rsi_mac80211_detach(struct rsi_hw *adapter)
{
	struct ieee80211_hw *hw = adapter->hw;
	enum nl80211_band band;

	if (hw) {
		ieee80211_stop_queues(hw);
		ieee80211_unregister_hw(hw);
		ieee80211_free_hw(hw);
	}

	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		struct ieee80211_supported_band *sband =
					&adapter->sbands[band];

		kfree(sband->channels);
	}

#ifdef CONFIG_RSI_DEBUGFS
	rsi_remove_dbgfs(adapter);
	kfree(adapter->dfsentry);
#endif
}
