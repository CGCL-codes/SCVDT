int vnc_raw_send_framebuffer_update(VncState *vs, int x, int y, int w, int h)
{
    int i;
    uint8_t *row;
    VncDisplay *vd = vs->vd;

    row = vnc_server_fb_ptr(vd, x, y);
    for (i = 0; i < h; i++) {
        vs->write_pixels(vs, row, w * VNC_SERVER_FB_BYTES);
        row += vnc_server_fb_stride(vd);
    }
    return 1;
}
