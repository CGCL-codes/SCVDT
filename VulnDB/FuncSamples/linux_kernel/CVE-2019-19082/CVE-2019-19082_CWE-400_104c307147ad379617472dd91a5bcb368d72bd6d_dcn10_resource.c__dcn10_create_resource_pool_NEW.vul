struct resource_pool *dcn10_create_resource_pool(
		const struct dc_init_data *init_data,
		struct dc *dc)
{
	struct dcn10_resource_pool *pool =
		kzalloc(sizeof(struct dcn10_resource_pool), GFP_KERNEL);

	if (!pool)
		return NULL;

	if (construct(init_data->num_virtual_links, dc, pool))
		return &pool->base;

	kfree(pool);
	BREAK_TO_DEBUGGER();
	return NULL;
}
