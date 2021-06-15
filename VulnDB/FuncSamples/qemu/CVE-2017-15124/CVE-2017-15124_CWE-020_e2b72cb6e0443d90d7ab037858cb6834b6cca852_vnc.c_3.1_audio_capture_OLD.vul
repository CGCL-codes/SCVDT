static void audio_capture(void *opaque, void *buf, int size)
{
    VncState *vs = opaque;

    vnc_lock_output(vs);
    vnc_write_u8(vs, VNC_MSG_SERVER_QEMU);
    vnc_write_u8(vs, VNC_MSG_SERVER_QEMU_AUDIO);
    vnc_write_u16(vs, VNC_MSG_SERVER_QEMU_AUDIO_DATA);
    vnc_write_u32(vs, size);
    vnc_write(vs, buf, size);
    vnc_unlock_output(vs);
    vnc_flush(vs);
}
