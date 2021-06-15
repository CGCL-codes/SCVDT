struct resource_pool *dce110_create_resource_pool(
	uint8_t num_virtual_links,
	struct dc *dc,
	struct hw_asic_id asic_id)
{
	struct dce110_resource_pool *pool =
		kzalloc(sizeof(struct dce110_resource_pool), GFP_KERNEL);

	if (!pool)
		return NULL;

	if (construct(num_virtual_links, dc, pool, asic_id))
		return &pool->base;

	BREAK_TO_DEBUGGER();
	return NULL;
}
