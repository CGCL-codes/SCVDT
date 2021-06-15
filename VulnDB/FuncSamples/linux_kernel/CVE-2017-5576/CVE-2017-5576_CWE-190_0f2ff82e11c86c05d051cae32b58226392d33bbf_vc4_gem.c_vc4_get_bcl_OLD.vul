static int
vc4_get_bcl(struct drm_device *dev, struct vc4_exec_info *exec)
{
	struct drm_vc4_submit_cl *args = exec->args;
	void *temp = NULL;
	void *bin;
	int ret = 0;
	uint32_t bin_offset = 0;
	uint32_t shader_rec_offset = roundup(bin_offset + args->bin_cl_size,
					     16);
	uint32_t uniforms_offset = shader_rec_offset + args->shader_rec_size;
	uint32_t exec_size = uniforms_offset + args->uniforms_size;
	uint32_t temp_size = exec_size + (sizeof(struct vc4_shader_state) *
					  args->shader_rec_count);
	struct vc4_bo *bo;

	if (uniforms_offset < shader_rec_offset ||
	    exec_size < uniforms_offset ||
	    args->shader_rec_count >= (UINT_MAX /
					  sizeof(struct vc4_shader_state)) ||
	    temp_size < exec_size) {
		DRM_ERROR("overflow in exec arguments\n");
		goto fail;
	}

	/* Allocate space where we'll store the copied in user command lists
	 * and shader records.
	 *
	 * We don't just copy directly into the BOs because we need to
	 * read the contents back for validation, and I think the
	 * bo->vaddr is uncached access.
	 */
	temp = drm_malloc_ab(temp_size, 1);
	if (!temp) {
		DRM_ERROR("Failed to allocate storage for copying "
			  "in bin/render CLs.\n");
		ret = -ENOMEM;
		goto fail;
	}
	bin = temp + bin_offset;
	exec->shader_rec_u = temp + shader_rec_offset;
	exec->uniforms_u = temp + uniforms_offset;
	exec->shader_state = temp + exec_size;
	exec->shader_state_size = args->shader_rec_count;

	if (copy_from_user(bin,
			   (void __user *)(uintptr_t)args->bin_cl,
			   args->bin_cl_size)) {
		ret = -EFAULT;
		goto fail;
	}

	if (copy_from_user(exec->shader_rec_u,
			   (void __user *)(uintptr_t)args->shader_rec,
			   args->shader_rec_size)) {
		ret = -EFAULT;
		goto fail;
	}

	if (copy_from_user(exec->uniforms_u,
			   (void __user *)(uintptr_t)args->uniforms,
			   args->uniforms_size)) {
		ret = -EFAULT;
		goto fail;
	}

	bo = vc4_bo_create(dev, exec_size, true);
	if (IS_ERR(bo)) {
		DRM_ERROR("Couldn't allocate BO for binning\n");
		ret = PTR_ERR(bo);
		goto fail;
	}
	exec->exec_bo = &bo->base;

	list_add_tail(&to_vc4_bo(&exec->exec_bo->base)->unref_head,
		      &exec->unref_list);

	exec->ct0ca = exec->exec_bo->paddr + bin_offset;

	exec->bin_u = bin;

	exec->shader_rec_v = exec->exec_bo->vaddr + shader_rec_offset;
	exec->shader_rec_p = exec->exec_bo->paddr + shader_rec_offset;
	exec->shader_rec_size = args->shader_rec_size;

	exec->uniforms_v = exec->exec_bo->vaddr + uniforms_offset;
	exec->uniforms_p = exec->exec_bo->paddr + uniforms_offset;
	exec->uniforms_size = args->uniforms_size;

	ret = vc4_validate_bin_cl(dev,
				  exec->exec_bo->vaddr + bin_offset,
				  bin,
				  exec);
	if (ret)
		goto fail;

	ret = vc4_validate_shader_recs(dev, exec);
	if (ret)
		goto fail;

	/* Block waiting on any previous rendering into the CS's VBO,
	 * IB, or textures, so that pixels are actually written by the
	 * time we try to read them.
	 */
	ret = vc4_wait_for_seqno(dev, exec->bin_dep_seqno, ~0ull, true);

fail:
	drm_free_large(temp);
	return ret;
}
