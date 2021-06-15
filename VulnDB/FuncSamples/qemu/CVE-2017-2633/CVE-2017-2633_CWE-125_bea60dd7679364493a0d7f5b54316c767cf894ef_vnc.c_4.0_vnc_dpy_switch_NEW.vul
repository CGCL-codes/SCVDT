static void vnc_dpy_switch(DisplayChangeListener *dcl,
                           DisplaySurface *surface)
{
    VncDisplay *vd = container_of(dcl, VncDisplay, dcl);
    VncState *vs;
    int width, height;

    vnc_abort_display_jobs(vd);

    /* server surface */
    qemu_pixman_image_unref(vd->server);
    vd->ds = surface;
    width = MIN(VNC_MAX_WIDTH, ROUND_UP(surface_width(vd->ds),
                                        VNC_DIRTY_PIXELS_PER_BIT));
    height = MIN(VNC_MAX_HEIGHT, surface_height(vd->ds));
    vd->server = pixman_image_create_bits(VNC_SERVER_FB_FORMAT,
                                          width, height, NULL, 0);

    /* guest surface */
#if 0 /* FIXME */
    if (ds_get_bytes_per_pixel(ds) != vd->guest.ds->pf.bytes_per_pixel)
        console_color_init(ds);
#endif
    qemu_pixman_image_unref(vd->guest.fb);
    vd->guest.fb = pixman_image_ref(surface->image);
    vd->guest.format = surface->format;
    memset(vd->guest.dirty, 0x00, sizeof(vd->guest.dirty));
    vnc_set_area_dirty(vd->guest.dirty, width, height, 0, 0,
                       width, height);

    QTAILQ_FOREACH(vs, &vd->clients, next) {
        vnc_colordepth(vs);
        vnc_desktop_resize(vs);
        if (vs->vd->cursor) {
            vnc_cursor_define(vs);
        }
        memset(vs->dirty, 0x00, sizeof(vs->dirty));
        vnc_set_area_dirty(vs->dirty, width, height, 0, 0,
                           width, height);
    }
}
