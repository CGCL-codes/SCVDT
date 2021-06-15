static void vnc_colordepth(VncState *vs)
{
    if (vnc_has_feature(vs, VNC_FEATURE_WMVI)) {
        /* Sending a WMVi message to notify the client*/
        vnc_lock_output(vs);
        vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
        vnc_write_u8(vs, 0);
        vnc_write_u16(vs, 1); /* number of rects */
        vnc_framebuffer_update(vs, 0, 0,
                               pixman_image_get_width(vs->vd->server),
                               pixman_image_get_height(vs->vd->server),
                               VNC_ENCODING_WMVi);
        pixel_format_message(vs);
        vnc_unlock_output(vs);
        vnc_flush(vs);
    } else {
        set_pixel_conversion(vs);
    }
}
