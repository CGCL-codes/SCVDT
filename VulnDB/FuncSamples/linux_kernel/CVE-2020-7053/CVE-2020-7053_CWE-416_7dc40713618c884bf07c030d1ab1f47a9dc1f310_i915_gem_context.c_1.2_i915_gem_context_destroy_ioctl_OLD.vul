int i915_gem_context_destroy_ioctl(struct drm_device *dev, void *data,
				   struct drm_file *file)
{
	struct drm_i915_gem_context_destroy *args = data;
	struct drm_i915_file_private *file_priv = file->driver_priv;
	struct i915_gem_context *ctx;
	int ret;

	if (args->pad != 0)
		return -EINVAL;

	if (args->ctx_id == DEFAULT_CONTEXT_HANDLE)
		return -ENOENT;

	ctx = i915_gem_context_lookup(file_priv, args->ctx_id);
	if (!ctx)
		return -ENOENT;

	ret = mutex_lock_interruptible(&dev->struct_mutex);
	if (ret)
		goto out;

	idr_remove(&file_priv->context_idr, ctx->user_handle);
	context_close(ctx);

	mutex_unlock(&dev->struct_mutex);

out:
	i915_gem_context_put(ctx);
	return 0;
}
