void vnc_convert_pixel(VncState *vs, uint8_t *buf, uint32_t v)
{
    uint8_t r, g, b;

#if VNC_SERVER_FB_FORMAT == PIXMAN_FORMAT(32, PIXMAN_TYPE_ARGB, 0, 8, 8, 8)
    r = (((v & 0x00ff0000) >> 16) << vs->client_pf.rbits) >> 8;
    g = (((v & 0x0000ff00) >>  8) << vs->client_pf.gbits) >> 8;
    b = (((v & 0x000000ff) >>  0) << vs->client_pf.bbits) >> 8;
#else
# error need some bits here if you change VNC_SERVER_FB_FORMAT
#endif
    v = (r << vs->client_pf.rshift) |
        (g << vs->client_pf.gshift) |
        (b << vs->client_pf.bshift);
    switch (vs->client_pf.bytes_per_pixel) {
    case 1:
        buf[0] = v;
        break;
    case 2:
        if (vs->client_be) {
            buf[0] = v >> 8;
            buf[1] = v;
        } else {
            buf[1] = v >> 8;
            buf[0] = v;
        }
        break;
    default:
    case 4:
        if (vs->client_be) {
            buf[0] = v >> 24;
            buf[1] = v >> 16;
            buf[2] = v >> 8;
            buf[3] = v;
        } else {
            buf[3] = v >> 24;
            buf[2] = v >> 16;
            buf[1] = v >> 8;
            buf[0] = v;
        }
        break;
    }
}
