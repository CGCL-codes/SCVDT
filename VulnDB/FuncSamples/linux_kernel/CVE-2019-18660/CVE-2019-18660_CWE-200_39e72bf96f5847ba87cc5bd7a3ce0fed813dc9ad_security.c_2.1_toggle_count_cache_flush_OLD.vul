static void toggle_count_cache_flush(bool enable)
{
	if (!enable || !security_ftr_enabled(SEC_FTR_FLUSH_COUNT_CACHE)) {
		patch_instruction_site(&patch__call_flush_count_cache, PPC_INST_NOP);
		count_cache_flush_type = COUNT_CACHE_FLUSH_NONE;
		pr_info("count-cache-flush: software flush disabled.\n");
		return;
	}

	patch_branch_site(&patch__call_flush_count_cache,
			  (u64)&flush_count_cache, BRANCH_SET_LINK);

	if (!security_ftr_enabled(SEC_FTR_BCCTR_FLUSH_ASSIST)) {
		count_cache_flush_type = COUNT_CACHE_FLUSH_SW;
		pr_info("count-cache-flush: full software flush sequence enabled.\n");
		return;
	}

	patch_instruction_site(&patch__flush_count_cache_return, PPC_INST_BLR);
	count_cache_flush_type = COUNT_CACHE_FLUSH_HW;
	pr_info("count-cache-flush: hardware assisted flush sequence enabled\n");
}
