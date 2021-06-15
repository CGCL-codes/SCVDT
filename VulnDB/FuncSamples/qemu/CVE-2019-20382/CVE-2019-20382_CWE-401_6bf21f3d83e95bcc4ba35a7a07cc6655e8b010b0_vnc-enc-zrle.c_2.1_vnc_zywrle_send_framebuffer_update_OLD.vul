int vnc_zywrle_send_framebuffer_update(VncState *vs, int x, int y, int w, int h)
{
    vs->zrle.type = VNC_ENCODING_ZYWRLE;
    return zrle_send_framebuffer_update(vs, x, y, w, h);
}
