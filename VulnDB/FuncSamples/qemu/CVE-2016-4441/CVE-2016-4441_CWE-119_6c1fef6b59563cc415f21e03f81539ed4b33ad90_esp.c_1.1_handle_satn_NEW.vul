static void handle_satn(ESPState *s)
{
    uint8_t buf[32];
    int len;

    if (s->dma && !s->dma_enabled) {
        s->dma_cb = handle_satn;
        return;
    }
    len = get_cmd(s, buf, sizeof(buf));
    if (len)
        do_cmd(s, buf);
}
