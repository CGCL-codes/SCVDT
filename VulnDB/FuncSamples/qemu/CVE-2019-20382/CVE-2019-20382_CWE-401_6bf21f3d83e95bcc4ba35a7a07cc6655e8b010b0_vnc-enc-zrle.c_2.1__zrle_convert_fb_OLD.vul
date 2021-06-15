static void *zrle_convert_fb(VncState *vs, int x, int y, int w, int h,
                             int bpp)
{
    Buffer tmp;

    buffer_reset(&vs->zrle.fb);
    buffer_reserve(&vs->zrle.fb, w * h * bpp + bpp);

    tmp = vs->output;
    vs->output = vs->zrle.fb;

    vnc_raw_send_framebuffer_update(vs, x, y, w, h);

    vs->zrle.fb = vs->output;
    vs->output = tmp;
    return vs->zrle.fb.buffer;
}
