static int cirrus_bitblt_videotovideo_patterncopy(CirrusVGAState * s)
{
    return cirrus_bitblt_common_patterncopy(s,
					    s->vram_ptr +
                                            (s->cirrus_blt_srcaddr & ~7));
}
