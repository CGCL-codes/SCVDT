static void check_pointer_type_change(Notifier *notifier, void *data)
{
    VncState *vs = container_of(notifier, VncState, mouse_mode_notifier);
    int absolute = qemu_input_is_absolute();

    if (vnc_has_feature(vs, VNC_FEATURE_POINTER_TYPE_CHANGE) && vs->absolute != absolute) {
        vnc_lock_output(vs);
        vnc_write_u8(vs, VNC_MSG_SERVER_FRAMEBUFFER_UPDATE);
        vnc_write_u8(vs, 0);
        vnc_write_u16(vs, 1);
        vnc_framebuffer_update(vs, absolute, 0,
                               pixman_image_get_width(vs->vd->server),
                               pixman_image_get_height(vs->vd->server),
                               VNC_ENCODING_POINTER_TYPE_CHANGE);
        vnc_unlock_output(vs);
        vnc_flush(vs);
    }
    vs->absolute = absolute;
}
