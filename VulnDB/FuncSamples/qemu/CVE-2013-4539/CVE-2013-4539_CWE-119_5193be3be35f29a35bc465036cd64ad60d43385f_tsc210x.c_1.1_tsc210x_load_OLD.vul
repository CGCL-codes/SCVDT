static int tsc210x_load(QEMUFile *f, void *opaque, int version_id)
{
    TSC210xState *s = (TSC210xState *) opaque;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    int i;

    s->x = qemu_get_be16(f);
    s->y = qemu_get_be16(f);
    s->pressure = qemu_get_byte(f);

    s->state = qemu_get_byte(f);
    s->page = qemu_get_byte(f);
    s->offset = qemu_get_byte(f);
    s->command = qemu_get_byte(f);

    s->irq = qemu_get_byte(f);
    qemu_get_be16s(f, &s->dav);

    timer_get(f, s->timer);
    s->enabled = qemu_get_byte(f);
    s->host_mode = qemu_get_byte(f);
    s->function = qemu_get_byte(f);
    s->nextfunction = qemu_get_byte(f);
    s->precision = qemu_get_byte(f);
    s->nextprecision = qemu_get_byte(f);
    s->filter = qemu_get_byte(f);
    s->pin_func = qemu_get_byte(f);
    s->ref = qemu_get_byte(f);
    s->timing = qemu_get_byte(f);
    s->noise = qemu_get_be32(f);

    qemu_get_be16s(f, &s->audio_ctrl1);
    qemu_get_be16s(f, &s->audio_ctrl2);
    qemu_get_be16s(f, &s->audio_ctrl3);
    qemu_get_be16s(f, &s->pll[0]);
    qemu_get_be16s(f, &s->pll[1]);
    qemu_get_be16s(f, &s->volume);
    s->volume_change = qemu_get_sbe64(f) + now;
    s->powerdown = qemu_get_sbe64(f) + now;
    s->softstep = qemu_get_byte(f);
    qemu_get_be16s(f, &s->dac_power);

    for (i = 0; i < 0x14; i ++)
        qemu_get_be16s(f, &s->filter_data[i]);

    s->busy = timer_pending(s->timer);
    qemu_set_irq(s->pint, !s->irq);
    qemu_set_irq(s->davint, !s->dav);

    return 0;
}
