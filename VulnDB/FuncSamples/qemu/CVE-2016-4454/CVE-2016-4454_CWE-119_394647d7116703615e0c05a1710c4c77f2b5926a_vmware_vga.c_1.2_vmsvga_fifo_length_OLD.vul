static inline int vmsvga_fifo_length(struct vmsvga_state_s *s)
{
    int num;

    if (!s->config || !s->enable) {
        return 0;
    }
    num = CMD(next_cmd) - CMD(stop);
    if (num < 0) {
        num += CMD(max) - CMD(min);
    }
    return num >> 2;
}
