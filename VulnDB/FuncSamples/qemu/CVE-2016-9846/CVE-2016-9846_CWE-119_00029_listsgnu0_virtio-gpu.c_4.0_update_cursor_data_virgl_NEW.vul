static void update_cursor_data_virgl(VirtIOGPU *g,
                                     struct virtio_gpu_scanout *s,
                                     uint32_t resource_id)
{
    uint32_t width, height;
    uint32_t pixels, *data;

    data = virgl_renderer_get_cursor_data(resource_id, &width, &height);
    if (!data) {
        return;
    }

    if (width != s->current_cursor->width ||
        height != s->current_cursor->height) {
        free(data);
        return;
    }

    pixels = s->current_cursor->width * s->current_cursor->height;
    memcpy(s->current_cursor->data, data, pixels * sizeof(uint32_t));
    free(data);
}
