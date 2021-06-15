static void cirrus_invalidate_region(CirrusVGAState * s, int off_begin,
				     int off_pitch, int bytesperline,
				     int lines)
{
    int y;
    int off_cur;
    int off_cur_end;

    for (y = 0; y < lines; y++) {
	off_cur = off_begin;
	off_cur_end = (off_cur + bytesperline) & s->cirrus_addr_mask;
        memory_region_set_dirty(&s->vga.vram, off_cur, off_cur_end - off_cur);
	off_begin += off_pitch;
    }
}
