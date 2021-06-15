static inline int vmsvga_fifo_length(struct vmsvga_state_s *s)
{
    int num;

    if (!s->config || !s->enable) {
        return 0;
    }

    s->fifo_min  = le32_to_cpu(s->fifo[SVGA_FIFO_MIN]);
    s->fifo_max  = le32_to_cpu(s->fifo[SVGA_FIFO_MAX]);
    s->fifo_next = le32_to_cpu(s->fifo[SVGA_FIFO_NEXT]);
    s->fifo_stop = le32_to_cpu(s->fifo[SVGA_FIFO_STOP]);

    /* Check range and alignment.  */
    if ((s->fifo_min | s->fifo_max | s->fifo_next | s->fifo_stop) & 3) {
        return 0;
    }
    if (s->fifo_min < sizeof(uint32_t) * 4) {
        return 0;
    }
    if (s->fifo_max > SVGA_FIFO_SIZE ||
        s->fifo_min >= SVGA_FIFO_SIZE ||
        s->fifo_stop >= SVGA_FIFO_SIZE ||
        s->fifo_next >= SVGA_FIFO_SIZE) {
        return 0;
    }
    if (s->fifo_max < s->fifo_min + 10 * 1024) {
        return 0;
    }

    num = s->fifo_next - s->fifo_stop;
    if (num < 0) {
        num += s->fifo_max - s->fifo_min;
    }
    return num >> 2;
}
