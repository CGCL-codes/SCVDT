static void framebuffer_update_request(VncState *vs, int incremental,
                                       int x_position, int y_position,
                                       int w, int h)
{
    int i;
    const size_t width = surface_width(vs->vd->ds) / VNC_DIRTY_PIXELS_PER_BIT;
    const size_t height = surface_height(vs->vd->ds);

    if (y_position > height) {
        y_position = height;
    }
    if (y_position + h >= height) {
        h = height - y_position;
    }

    vs->need_update = 1;
    if (!incremental) {
        vs->force_update = 1;
        for (i = 0; i < h; i++) {
            bitmap_set(vs->dirty[y_position + i], 0, width);
            bitmap_clear(vs->dirty[y_position + i], width,
                         VNC_DIRTY_BITS - width);
        }
    }
}
