int
v3d_submit_cl_ioctl(struct drm_device *dev, void *data,
		    struct drm_file *file_priv)
{
	struct v3d_dev *v3d = to_v3d_dev(dev);
	struct v3d_file_priv *v3d_priv = file_priv->driver_priv;
	struct drm_v3d_submit_cl *args = data;
	struct v3d_bin_job *bin = NULL;
	struct v3d_render_job *render;
	struct ww_acquire_ctx acquire_ctx;
	int ret = 0;

	trace_v3d_submit_cl_ioctl(&v3d->drm, args->rcl_start, args->rcl_end);

	if (args->pad != 0) {
		DRM_INFO("pad must be zero: %d\n", args->pad);
		return -EINVAL;
	}

	render = kcalloc(1, sizeof(*render), GFP_KERNEL);
	if (!render)
		return -ENOMEM;

	render->start = args->rcl_start;
	render->end = args->rcl_end;
	INIT_LIST_HEAD(&render->unref_list);

	ret = v3d_job_init(v3d, file_priv, &render->base,
			   v3d_render_job_free, args->in_sync_rcl);
	if (ret) {
		kfree(render);
		return ret;
	}

	if (args->bcl_start != args->bcl_end) {
		bin = kcalloc(1, sizeof(*bin), GFP_KERNEL);
		if (!bin)
			return -ENOMEM;

		ret = v3d_job_init(v3d, file_priv, &bin->base,
				   v3d_job_free, args->in_sync_bcl);
		if (ret) {
			v3d_job_put(&render->base);
			return ret;
		}

		bin->start = args->bcl_start;
		bin->end = args->bcl_end;
		bin->qma = args->qma;
		bin->qms = args->qms;
		bin->qts = args->qts;
		bin->render = render;
	}

	ret = v3d_lookup_bos(dev, file_priv, &render->base,
			     args->bo_handles, args->bo_handle_count);
	if (ret)
		goto fail;

	ret = v3d_lock_bo_reservations(&render->base, &acquire_ctx);
	if (ret)
		goto fail;

	mutex_lock(&v3d->sched_lock);
	if (bin) {
		ret = v3d_push_job(v3d_priv, &bin->base, V3D_BIN);
		if (ret)
			goto fail_unreserve;

		ret = drm_gem_fence_array_add(&render->base.deps,
					      dma_fence_get(bin->base.done_fence));
		if (ret)
			goto fail_unreserve;
	}

	ret = v3d_push_job(v3d_priv, &render->base, V3D_RENDER);
	if (ret)
		goto fail_unreserve;
	mutex_unlock(&v3d->sched_lock);

	v3d_attach_fences_and_unlock_reservation(file_priv,
						 &render->base,
						 &acquire_ctx,
						 args->out_sync,
						 render->base.done_fence);

	if (bin)
		v3d_job_put(&bin->base);
	v3d_job_put(&render->base);

	return 0;

fail_unreserve:
	mutex_unlock(&v3d->sched_lock);
	drm_gem_unlock_reservations(render->base.bo,
				    render->base.bo_count, &acquire_ctx);
fail:
	if (bin)
		v3d_job_put(&bin->base);
	v3d_job_put(&render->base);

	return ret;
}
