static void set_pixel_conversion(VncState *vs)
{
    pixman_format_code_t fmt = qemu_pixman_get_format(&vs->client_pf);

    if (fmt == VNC_SERVER_FB_FORMAT) {
        vs->write_pixels = vnc_write_pixels_copy;
        vnc_hextile_set_pixel_conversion(vs, 0);
    } else {
        vs->write_pixels = vnc_write_pixels_generic;
        vnc_hextile_set_pixel_conversion(vs, 1);
    }
}
