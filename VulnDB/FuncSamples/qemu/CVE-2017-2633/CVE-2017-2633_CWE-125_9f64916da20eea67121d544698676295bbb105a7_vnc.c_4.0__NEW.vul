static void pixel_format_message (VncState *vs) {
    char pad[3] = { 0, 0, 0 };

    vs->client_pf = qemu_default_pixelformat(32);

    vnc_write_u8(vs, vs->client_pf.bits_per_pixel); /* bits-per-pixel */
    vnc_write_u8(vs, vs->client_pf.depth); /* depth */

#ifdef HOST_WORDS_BIGENDIAN
    vnc_write_u8(vs, 1);             /* big-endian-flag */
#else
    vnc_write_u8(vs, 0);             /* big-endian-flag */
#endif
    vnc_write_u8(vs, 1);             /* true-color-flag */
    vnc_write_u16(vs, vs->client_pf.rmax);     /* red-max */
    vnc_write_u16(vs, vs->client_pf.gmax);     /* green-max */
    vnc_write_u16(vs, vs->client_pf.bmax);     /* blue-max */
    vnc_write_u8(vs, vs->client_pf.rshift);    /* red-shift */
    vnc_write_u8(vs, vs->client_pf.gshift);    /* green-shift */
    vnc_write_u8(vs, vs->client_pf.bshift);    /* blue-shift */
    vnc_write(vs, pad, 3);           /* padding */

    vnc_hextile_set_pixel_conversion(vs, 0);
    vs->write_pixels = vnc_write_pixels_copy;
}
