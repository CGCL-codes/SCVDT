static void send_ext_audio_ack(VncState *vs)
{
    vnc_lock_output(vs);
    vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
    vnc_write_u8(vs, 0);
    vnc_write_u16(vs, 1);
    vnc_framebuffer_update(vs, 0, 0,
                           surface_width(vs->vd->ds),
                           surface_height(vs->vd->ds),
                           VNC_ENCODING_AUDIO);
    vnc_unlock_output(vs);
    vnc_flush(vs);
}
