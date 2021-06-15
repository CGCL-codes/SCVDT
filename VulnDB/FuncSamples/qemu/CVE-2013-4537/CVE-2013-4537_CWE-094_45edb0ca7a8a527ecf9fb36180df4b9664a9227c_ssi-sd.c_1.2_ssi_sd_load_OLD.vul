static int ssi_sd_load(QEMUFile *f, void *opaque, int version_id)
{
    SSISlave *ss = SSI_SLAVE(opaque);
    ssi_sd_state *s = (ssi_sd_state *)opaque;
    int i;

    if (version_id != 1)
        return -EINVAL;

    s->mode = qemu_get_be32(f);
    s->cmd = qemu_get_be32(f);
    for (i = 0; i < 4; i++)
        s->cmdarg[i] = qemu_get_be32(f);
    for (i = 0; i < 5; i++)
        s->response[i] = qemu_get_be32(f);
    s->arglen = qemu_get_be32(f);
    s->response_pos = qemu_get_be32(f);
    s->stopping = qemu_get_be32(f);

    ss->cs = qemu_get_be32(f);

    return 0;
}
