static struct ucma_multicast* ucma_alloc_multicast(struct ucma_context *ctx)
{
	struct ucma_multicast *mc;

	mc = kzalloc(sizeof(*mc), GFP_KERNEL);
	if (!mc)
		return NULL;

	mutex_lock(&mut);
	mc->id = idr_alloc(&multicast_idr, mc, 0, 0, GFP_KERNEL);
	mutex_unlock(&mut);
	if (mc->id < 0)
		goto error;

	mc->ctx = ctx;
	list_add_tail(&mc->list, &ctx->mc_list);
	return mc;

error:
	kfree(mc);
	return NULL;
}
