static int cirrus_bitblt_common_patterncopy(CirrusVGAState * s,
					    const uint8_t * src)
{
    uint8_t *dst;

    dst = s->vram_ptr + (s->cirrus_blt_dstaddr & s->cirrus_addr_mask);

    if (BLTUNSAFE(s))
        return 0;

    (*s->cirrus_rop) (s, dst, src,
                      s->cirrus_blt_dstpitch, 0,
                      s->cirrus_blt_width, s->cirrus_blt_height);
    cirrus_invalidate_region(s, s->cirrus_blt_dstaddr,
                             s->cirrus_blt_dstpitch, s->cirrus_blt_width,
                             s->cirrus_blt_height);
    return 1;
}
