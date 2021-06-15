static int cirrus_bitblt_videotovideo_copy(CirrusVGAState * s)
{
    if (s->ds->dpy_copy) {
	cirrus_do_copy(s, s->cirrus_blt_dstaddr - s->start_addr,
		       s->cirrus_blt_srcaddr - s->start_addr,
		       s->cirrus_blt_width, s->cirrus_blt_height);
    } else {
	(*s->cirrus_rop) (s, s->vram_ptr + s->cirrus_blt_dstaddr,
			  s->vram_ptr + s->cirrus_blt_srcaddr,
			  s->cirrus_blt_dstpitch, s->cirrus_blt_srcpitch,
			  s->cirrus_blt_width, s->cirrus_blt_height);

	cirrus_invalidate_region(s, s->cirrus_blt_dstaddr,
				 s->cirrus_blt_dstpitch, s->cirrus_blt_width,
				 s->cirrus_blt_height);
    }

    return 1;
}
