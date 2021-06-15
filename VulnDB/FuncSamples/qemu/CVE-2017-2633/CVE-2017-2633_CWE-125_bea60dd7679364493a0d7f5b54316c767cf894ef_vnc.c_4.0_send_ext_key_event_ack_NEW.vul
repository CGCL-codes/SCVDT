static void send_ext_key_event_ack(VncState *vs)
{
    vnc_lock_output(vs);
    vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1);
    vnc_framebuffer_update(vs, 0, 0,
                           pixman_image_get_width(vs->vd->server),
                           pixman_image_get_height(vs->vd->server),
                           VNC_ENCODING_EXT_KEY_EVENT);
    vnc_unlock_output(vs);
    vnc_flush(vs);
}
