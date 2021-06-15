static bool blit_region_is_unsafe(struct CirrusVGAState *s,
                                  int32_t pitch, int32_t addr)
{
    if (!pitch) {
        return true;
    }
    if (pitch < 0) {
        int64_t min = addr
            + ((int64_t)s->cirrus_blt_height-1) * pitch;
        int32_t max = addr
            + s->cirrus_blt_width;
        if (min < 0 || max > s->vga.vram_size) {
            return true;
        }
    } else {
        int64_t max = addr
            + ((int64_t)s->cirrus_blt_height-1) * pitch
            + s->cirrus_blt_width;
        if (max > s->vga.vram_size) {
            return true;
        }
    }
    return false;
}
