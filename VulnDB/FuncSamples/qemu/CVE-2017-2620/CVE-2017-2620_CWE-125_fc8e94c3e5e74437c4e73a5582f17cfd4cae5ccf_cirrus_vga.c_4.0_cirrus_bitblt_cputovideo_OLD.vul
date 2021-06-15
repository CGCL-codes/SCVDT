static int cirrus_bitblt_cputovideo(CirrusVGAState * s)
{
    int w;

    s->cirrus_blt_mode &= ~CIRRUS_BLTMODE_MEMSYSSRC;
    s->cirrus_srcptr = &s->cirrus_bltbuf[0];
    s->cirrus_srcptr_end = &s->cirrus_bltbuf[0];

    if (s->cirrus_blt_mode & CIRRUS_BLTMODE_PATTERNCOPY) {
	if (s->cirrus_blt_mode & CIRRUS_BLTMODE_COLOREXPAND) {
	    s->cirrus_blt_srcpitch = 8;
	} else {
            /* XXX: check for 24 bpp */
	    s->cirrus_blt_srcpitch = 8 * 8 * s->cirrus_blt_pixelwidth;
	}
	s->cirrus_srccounter = s->cirrus_blt_srcpitch;
    } else {
	if (s->cirrus_blt_mode & CIRRUS_BLTMODE_COLOREXPAND) {
            w = s->cirrus_blt_width / s->cirrus_blt_pixelwidth;
            if (s->cirrus_blt_modeext & CIRRUS_BLTMODEEXT_DWORDGRANULARITY)
                s->cirrus_blt_srcpitch = ((w + 31) >> 5);
            else
                s->cirrus_blt_srcpitch = ((w + 7) >> 3);
	} else {
            /* always align input size to 32 bits */
	    s->cirrus_blt_srcpitch = (s->cirrus_blt_width + 3) & ~3;
	}
        s->cirrus_srccounter = s->cirrus_blt_srcpitch * s->cirrus_blt_height;
    }
    s->cirrus_srcptr = s->cirrus_bltbuf;
    s->cirrus_srcptr_end = s->cirrus_bltbuf + s->cirrus_blt_srcpitch;
    cirrus_update_memory_access(s);
    return 1;
}
