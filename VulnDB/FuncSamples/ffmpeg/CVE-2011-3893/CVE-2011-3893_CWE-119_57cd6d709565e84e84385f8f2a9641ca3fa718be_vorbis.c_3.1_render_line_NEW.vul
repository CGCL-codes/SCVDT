static void render_line(int x0, uint8_t y0, int x1, int y1, float *buf)
{
    int dy  = y1 - y0;
    int adx = x1 - x0;
    int ady = FFABS(dy);
    int sy  = dy < 0 ? -1 : 1;
    buf[x0] = ff_vorbis_floor1_inverse_db_table[y0];
    if (ady*2 <= adx) { // optimized common case
        render_line_unrolled(x0, y0, x1, sy, ady, adx, buf);
    } else {
        int base  = dy / adx;
        int x     = x0;
        uint8_t y = y0;
        int err   = -adx;
        ady -= FFABS(base) * adx;
        while (++x < x1) {
            y += base;
            err += ady;
            if (err >= 0) {
                err -= adx;
                y   += sy;
            }
            buf[x] = ff_vorbis_floor1_inverse_db_table[y];
        }
    }
}
