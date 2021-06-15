void ide_data_writel(void *opaque, uint32_t addr, uint32_t val)
{
    IDEBus *bus = opaque;
    IDEState *s = idebus_active_if(bus);
    uint8_t *p;

    /* PIO data access allowed only when DRQ bit is set. The result of a write
     * during PIO out is indeterminate, just ignore it. */
    if (!(s->status & DRQ_STAT) || ide_is_pio_out(s)) {
        return;
    }

    p = s->data_ptr;
    *(uint32_t *)p = le32_to_cpu(val);
    p += 4;
    s->data_ptr = p;
    if (p >= s->data_end)
        s->end_transfer_func(s);
}
