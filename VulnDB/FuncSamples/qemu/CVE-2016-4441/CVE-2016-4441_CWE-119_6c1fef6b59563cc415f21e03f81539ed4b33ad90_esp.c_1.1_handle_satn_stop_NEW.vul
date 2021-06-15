static void handle_satn_stop(ESPState *s)
{
    if (s->dma && !s->dma_enabled) {
        s->dma_cb = handle_satn_stop;
        return;
    }
    s->cmdlen = get_cmd(s, s->cmdbuf, sizeof(s->cmdbuf));
    if (s->cmdlen) {
        trace_esp_handle_satn_stop(s->cmdlen);
        s->do_cmd = 1;
        s->rregs[ESP_RSTAT] = STAT_TC | STAT_CD;
        s->rregs[ESP_RINTR] = INTR_BS | INTR_FC;
        s->rregs[ESP_RSEQ] = SEQ_CD;
        esp_raise_irq(s);
    }
}
