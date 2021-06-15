int i915_gem_context_open(struct drm_i915_private *i915,
			  struct drm_file *file)
{
	struct drm_i915_file_private *file_priv = file->driver_priv;
	struct i915_gem_context *ctx;
	int err;

	idr_init(&file_priv->context_idr);
	mutex_init(&file_priv->context_idr_lock);

	mutex_lock(&i915->drm.struct_mutex);
	ctx = i915_gem_create_context(i915);
	mutex_unlock(&i915->drm.struct_mutex);
	if (IS_ERR(ctx)) {
		err = PTR_ERR(ctx);
		goto err;
	}

	err = gem_context_register(ctx, file_priv);
	if (err)
		goto err_ctx;

	GEM_BUG_ON(ctx->user_handle != DEFAULT_CONTEXT_HANDLE);
	GEM_BUG_ON(i915_gem_context_is_kernel(ctx));

	return 0;

err_ctx:
	mutex_lock(&i915->drm.struct_mutex);
	context_close(ctx);
	mutex_unlock(&i915->drm.struct_mutex);
err:
	mutex_destroy(&file_priv->context_idr_lock);
	idr_destroy(&file_priv->context_idr);
	return PTR_ERR(ctx);
}
