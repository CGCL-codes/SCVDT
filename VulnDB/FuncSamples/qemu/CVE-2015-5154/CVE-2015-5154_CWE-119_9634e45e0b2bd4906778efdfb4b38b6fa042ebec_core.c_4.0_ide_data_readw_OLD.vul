uint32_t ide_data_readw(void *opaque, uint32_t addr)
{
    IDEBus *bus = opaque;
    IDEState *s = idebus_active_if(bus);
    uint8_t *p;
    int ret;

    /* PIO data access allowed only when DRQ bit is set. The result of a read
     * during PIO in is indeterminate, return 0 and don't move forward. */
    if (!(s->status & DRQ_STAT) || !ide_is_pio_out(s)) {
        return 0;
    }

    p = s->data_ptr;
    ret = cpu_to_le16(*(uint16_t *)p);
    p += 2;
    s->data_ptr = p;
    if (p >= s->data_end)
        s->end_transfer_func(s);
    return ret;
}
