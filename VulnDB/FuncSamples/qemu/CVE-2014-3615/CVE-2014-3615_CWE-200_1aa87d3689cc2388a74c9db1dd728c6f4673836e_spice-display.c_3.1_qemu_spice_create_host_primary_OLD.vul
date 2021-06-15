void qemu_spice_create_host_primary(SimpleSpiceDisplay *ssd)
{
    QXLDevSurfaceCreate surface;

    memset(&surface, 0, sizeof(surface));

    dprint(1, "%s/%d: %dx%d\n", __func__, ssd->qxl.id,
           surface_width(ssd->ds), surface_height(ssd->ds));

    surface.format     = SPICE_SURFACE_FMT_32_xRGB;
    surface.width      = surface_width(ssd->ds);
    surface.height     = surface_height(ssd->ds);
    surface.stride     = -surface.width * 4;
    surface.mouse_mode = true;
    surface.flags      = 0;
    surface.type       = 0;
    surface.mem        = (uintptr_t)ssd->buf;
    surface.group_id   = MEMSLOT_GROUP_HOST;

    qemu_spice_create_primary_surface(ssd, 0, &surface, QXL_SYNC);
}
