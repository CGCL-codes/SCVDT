static enum ucode_state __init
get_matching_model_microcode(int cpu, unsigned long start,
			     void *data, size_t size,
			     struct mc_saved_data *mc_saved_data,
			     unsigned long *mc_saved_in_initrd,
			     struct ucode_cpu_info *uci)
{
	u8 *ucode_ptr = data;
	unsigned int leftover = size;
	enum ucode_state state = UCODE_OK;
	unsigned int mc_size;
	struct microcode_header_intel *mc_header;
	struct microcode_intel *mc_saved_tmp[MAX_UCODE_COUNT];
	unsigned int mc_saved_count = mc_saved_data->mc_saved_count;
	int i;

	while (leftover) {
		mc_header = (struct microcode_header_intel *)ucode_ptr;

		mc_size = get_totalsize(mc_header);
		if (!mc_size || mc_size > leftover ||
			microcode_sanity_check(ucode_ptr, 0) < 0)
			break;

		leftover -= mc_size;

		/*
		 * Since APs with same family and model as the BSP may boot in
		 * the platform, we need to find and save microcode patches
		 * with the same family and model as the BSP.
		 */
		if (matching_model_microcode(mc_header, uci->cpu_sig.sig) !=
			 UCODE_OK) {
			ucode_ptr += mc_size;
			continue;
		}

		_save_mc(mc_saved_tmp, ucode_ptr, &mc_saved_count);

		ucode_ptr += mc_size;
	}

	if (leftover) {
		state = UCODE_ERROR;
		goto out;
	}

	if (mc_saved_count == 0) {
		state = UCODE_NFOUND;
		goto out;
	}

	for (i = 0; i < mc_saved_count; i++)
		mc_saved_in_initrd[i] = (unsigned long)mc_saved_tmp[i] - start;

	mc_saved_data->mc_saved_count = mc_saved_count;
out:
	return state;
}
