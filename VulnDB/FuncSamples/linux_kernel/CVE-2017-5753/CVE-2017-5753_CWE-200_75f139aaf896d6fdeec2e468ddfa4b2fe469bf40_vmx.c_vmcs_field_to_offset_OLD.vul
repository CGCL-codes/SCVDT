static inline short vmcs_field_to_offset(unsigned long field)
{
	BUILD_BUG_ON(ARRAY_SIZE(vmcs_field_to_offset_table) > SHRT_MAX);

	if (field >= ARRAY_SIZE(vmcs_field_to_offset_table) ||
	    vmcs_field_to_offset_table[field] == 0)
		return -ENOENT;

	return vmcs_field_to_offset_table[field];
}
