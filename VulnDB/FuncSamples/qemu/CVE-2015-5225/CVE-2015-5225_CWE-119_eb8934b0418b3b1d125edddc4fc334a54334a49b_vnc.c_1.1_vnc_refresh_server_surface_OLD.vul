static int vnc_refresh_server_surface(VncDisplay *vd)
{
    int width = MIN(pixman_image_get_width(vd->guest.fb),
                    pixman_image_get_width(vd->server));
    int height = MIN(pixman_image_get_height(vd->guest.fb),
                     pixman_image_get_height(vd->server));
    int cmp_bytes, server_stride, min_stride, guest_stride, y = 0;
    uint8_t *guest_row0 = NULL, *server_row0;
    VncState *vs;
    int has_dirty = 0;
    pixman_image_t *tmpbuf = NULL;

    struct timeval tv = { 0, 0 };

    if (!vd->non_adaptive) {
        gettimeofday(&tv, NULL);
        has_dirty = vnc_update_stats(vd, &tv);
    }

    /*
     * Walk through the guest dirty map.
     * Check and copy modified bits from guest to server surface.
     * Update server dirty map.
     */
    server_row0 = (uint8_t *)pixman_image_get_data(vd->server);
    server_stride = guest_stride = pixman_image_get_stride(vd->server);
    cmp_bytes = MIN(VNC_DIRTY_PIXELS_PER_BIT * VNC_SERVER_FB_BYTES,
                    server_stride);
    if (vd->guest.format != VNC_SERVER_FB_FORMAT) {
        int width = pixman_image_get_width(vd->server);
        tmpbuf = qemu_pixman_linebuf_create(VNC_SERVER_FB_FORMAT, width);
    } else {
        guest_row0 = (uint8_t *)pixman_image_get_data(vd->guest.fb);
        guest_stride = pixman_image_get_stride(vd->guest.fb);
    }
    min_stride = MIN(server_stride, guest_stride);

    for (;;) {
        int x;
        uint8_t *guest_ptr, *server_ptr;
        unsigned long offset = find_next_bit((unsigned long *) &vd->guest.dirty,
                                             height * VNC_DIRTY_BPL(&vd->guest),
                                             y * VNC_DIRTY_BPL(&vd->guest));
        if (offset == height * VNC_DIRTY_BPL(&vd->guest)) {
            /* no more dirty bits */
            break;
        }
        y = offset / VNC_DIRTY_BPL(&vd->guest);
        x = offset % VNC_DIRTY_BPL(&vd->guest);

        server_ptr = server_row0 + y * server_stride + x * cmp_bytes;

        if (vd->guest.format != VNC_SERVER_FB_FORMAT) {
            qemu_pixman_linebuf_fill(tmpbuf, vd->guest.fb, width, 0, y);
            guest_ptr = (uint8_t *)pixman_image_get_data(tmpbuf);
        } else {
            guest_ptr = guest_row0 + y * guest_stride;
        }
        guest_ptr += x * cmp_bytes;

        for (; x < DIV_ROUND_UP(width, VNC_DIRTY_PIXELS_PER_BIT);
             x++, guest_ptr += cmp_bytes, server_ptr += cmp_bytes) {
            int _cmp_bytes = cmp_bytes;
            if (!test_and_clear_bit(x, vd->guest.dirty[y])) {
                continue;
            }
            if ((x + 1) * cmp_bytes > min_stride) {
                _cmp_bytes = min_stride - x * cmp_bytes;
            }
            if (memcmp(server_ptr, guest_ptr, _cmp_bytes) == 0) {
                continue;
            }
            memcpy(server_ptr, guest_ptr, _cmp_bytes);
            if (!vd->non_adaptive) {
                vnc_rect_updated(vd, x * VNC_DIRTY_PIXELS_PER_BIT,
                                 y, &tv);
            }
            QTAILQ_FOREACH(vs, &vd->clients, next) {
                set_bit(x, vs->dirty[y]);
            }
            has_dirty++;
        }

        y++;
    }
    qemu_pixman_image_unref(tmpbuf);
    return has_dirty;
}
