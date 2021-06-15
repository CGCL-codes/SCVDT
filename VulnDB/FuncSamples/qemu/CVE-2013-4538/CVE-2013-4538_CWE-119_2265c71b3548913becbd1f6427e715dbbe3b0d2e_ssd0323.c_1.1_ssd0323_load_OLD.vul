static int ssd0323_load(QEMUFile *f, void *opaque, int version_id)
{
    SSISlave *ss = SSI_SLAVE(opaque);
    ssd0323_state *s = (ssd0323_state *)opaque;
    int i;

    if (version_id != 1)
        return -EINVAL;

    s->cmd_len = qemu_get_be32(f);
    s->cmd = qemu_get_be32(f);
    for (i = 0; i < 8; i++)
        s->cmd_data[i] = qemu_get_be32(f);
    s->row = qemu_get_be32(f);
    s->row_start = qemu_get_be32(f);
    s->row_end = qemu_get_be32(f);
    s->col = qemu_get_be32(f);
    s->col_start = qemu_get_be32(f);
    s->col_end = qemu_get_be32(f);
    s->redraw = qemu_get_be32(f);
    s->remap = qemu_get_be32(f);
    s->mode = qemu_get_be32(f);
    qemu_get_buffer(f, s->framebuffer, sizeof(s->framebuffer));

    ss->cs = qemu_get_be32(f);

    return 0;
}
