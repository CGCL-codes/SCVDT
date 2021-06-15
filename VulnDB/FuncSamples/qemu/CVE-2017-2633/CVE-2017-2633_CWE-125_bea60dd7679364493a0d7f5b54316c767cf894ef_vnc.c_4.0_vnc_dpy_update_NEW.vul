static void vnc_dpy_update(DisplayChangeListener *dcl,
                           int x, int y, int w, int h)
{
    VncDisplay *vd = container_of(dcl, VncDisplay, dcl);
    struct VncSurface *s = &vd->guest;
    int width = pixman_image_get_width(vd->server);
    int height = pixman_image_get_height(vd->server);

    vnc_set_area_dirty(s->dirty, width, height, x, y, w, h);
}
