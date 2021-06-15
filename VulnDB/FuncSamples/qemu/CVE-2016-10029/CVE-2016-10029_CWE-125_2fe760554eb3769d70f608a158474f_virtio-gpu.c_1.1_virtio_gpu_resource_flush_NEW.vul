static void virtio_gpu_resource_flush(VirtIOGPU *g,
                                      struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_simple_resource *res;
    struct virtio_gpu_resource_flush rf;
    pixman_region16_t flush_region;
    int i;

    VIRTIO_GPU_FILL_CMD(rf);
    trace_virtio_gpu_cmd_res_flush(rf.resource_id,
                                   rf.r.width, rf.r.height, rf.r.x, rf.r.y);

    res = virtio_gpu_find_resource(g, rf.resource_id);
    if (!res) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal resource specified %d\n",
                      __func__, rf.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }

    if (rf.r.x > res->width ||
        rf.r.y > res->height ||
        rf.r.width > res->width ||
        rf.r.height > res->height ||
        rf.r.x + rf.r.width > res->width ||
        rf.r.y + rf.r.height > res->height) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: flush bounds outside resource"
                      " bounds for resource %d: %d %d %d %d vs %d %d\n",
                      __func__, rf.resource_id, rf.r.x, rf.r.y,
                      rf.r.width, rf.r.height, res->width, res->height);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        return;
    }

    pixman_region_init_rect(&flush_region,
                            rf.r.x, rf.r.y, rf.r.width, rf.r.height);
    for (i = 0; i < g->conf.max_outputs; i++) {
        struct virtio_gpu_scanout *scanout;
        pixman_region16_t region, finalregion;
        pixman_box16_t *extents;

        if (!(res->scanout_bitmask & (1 << i))) {
            continue;
        }
        scanout = &g->scanout[i];

        pixman_region_init(&finalregion);
        pixman_region_init_rect(&region, scanout->x, scanout->y,
                                scanout->width, scanout->height);

        pixman_region_intersect(&finalregion, &flush_region, &region);
        pixman_region_translate(&finalregion, -scanout->x, -scanout->y);
        extents = pixman_region_extents(&finalregion);
        /* work out the area we need to update for each console */
        dpy_gfx_update(g->scanout[i].con,
                       extents->x1, extents->y1,
                       extents->x2 - extents->x1,
                       extents->y2 - extents->y1);

        pixman_region_fini(&region);
        pixman_region_fini(&finalregion);
    }
    pixman_region_fini(&flush_region);
}
