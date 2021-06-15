int i915_gem_context_destroy_ioctl(struct drm_device *dev, void *data,
				   struct drm_file *file)
{
	struct drm_i915_gem_context_destroy *args = data;
	struct drm_i915_file_private *file_priv = file->driver_priv;
	struct i915_gem_context *ctx;

	if (args->pad != 0)
		return -EINVAL;

	if (args->ctx_id == DEFAULT_CONTEXT_HANDLE)
		return -ENOENT;

	if (mutex_lock_interruptible(&file_priv->context_idr_lock))
		return -EINTR;

	ctx = idr_remove(&file_priv->context_idr, args->ctx_id);
	mutex_unlock(&file_priv->context_idr_lock);
	if (!ctx)
		return -ENOENT;

	mutex_lock(&dev->struct_mutex);
	context_close(ctx);
	mutex_unlock(&dev->struct_mutex);

	return 0;
}
