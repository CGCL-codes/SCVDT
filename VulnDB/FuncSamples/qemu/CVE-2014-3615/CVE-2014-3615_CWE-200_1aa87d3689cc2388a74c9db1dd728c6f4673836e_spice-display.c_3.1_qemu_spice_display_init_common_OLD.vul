void qemu_spice_display_init_common(SimpleSpiceDisplay *ssd)
{
    qemu_mutex_init(&ssd->lock);
    QTAILQ_INIT(&ssd->updates);
    ssd->mouse_x = -1;
    ssd->mouse_y = -1;
    if (ssd->num_surfaces == 0) {
        ssd->num_surfaces = 1024;
    }
    ssd->bufsize = (16 * 1024 * 1024);
    ssd->buf = g_malloc(ssd->bufsize);
}
