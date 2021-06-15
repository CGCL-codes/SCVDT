static void handle_s_without_atn(ESPState *s)
{
    uint8_t buf[32];
    int len;

    if (s->dma && !s->dma_enabled) {
        s->dma_cb = handle_s_without_atn;
        return;
    }
    len = get_cmd(s, buf, sizeof(buf));
    if (len) {
        do_busid_cmd(s, buf, 0);
    }
}
