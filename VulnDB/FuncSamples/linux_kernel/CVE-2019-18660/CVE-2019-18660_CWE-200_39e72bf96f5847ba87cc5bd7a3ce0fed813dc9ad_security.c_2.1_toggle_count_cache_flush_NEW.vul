static void toggle_count_cache_flush(bool enable)
{
	if (!security_ftr_enabled(SEC_FTR_FLUSH_COUNT_CACHE) &&
	    !security_ftr_enabled(SEC_FTR_FLUSH_LINK_STACK))
		enable = false;

	if (!enable) {
		patch_instruction_site(&patch__call_flush_count_cache, PPC_INST_NOP);
		pr_info("link-stack-flush: software flush disabled.\n");
		link_stack_flush_enabled = false;
		no_count_cache_flush();
		return;
	}

	// This enables the branch from _switch to flush_count_cache
	patch_branch_site(&patch__call_flush_count_cache,
			  (u64)&flush_count_cache, BRANCH_SET_LINK);

	pr_info("link-stack-flush: software flush enabled.\n");
	link_stack_flush_enabled = true;

	// If we just need to flush the link stack, patch an early return
	if (!security_ftr_enabled(SEC_FTR_FLUSH_COUNT_CACHE)) {
		patch_instruction_site(&patch__flush_link_stack_return, PPC_INST_BLR);
		no_count_cache_flush();
		return;
	}

	if (!security_ftr_enabled(SEC_FTR_BCCTR_FLUSH_ASSIST)) {
		count_cache_flush_type = COUNT_CACHE_FLUSH_SW;
		pr_info("count-cache-flush: full software flush sequence enabled.\n");
		return;
	}

	patch_instruction_site(&patch__flush_count_cache_return, PPC_INST_BLR);
	count_cache_flush_type = COUNT_CACHE_FLUSH_HW;
	pr_info("count-cache-flush: hardware assisted flush sequence enabled\n");
}
