static void cirrus_mem_writeb_mode4and5_16bpp(CirrusVGAState * s,
					      unsigned mode,
					      unsigned offset,
					      uint32_t mem_value)
{
    int x;
    unsigned val = mem_value;
    uint8_t *dst;

    dst = s->vram_ptr + offset;
    for (x = 0; x < 8; x++) {
	if (val & 0x80) {
	    *dst = s->cirrus_shadow_gr1;
	    *(dst + 1) = s->gr[0x11];
	} else if (mode == 5) {
	    *dst = s->cirrus_shadow_gr0;
	    *(dst + 1) = s->gr[0x10];
	}
	val <<= 1;
	dst += 2;
    }
    cpu_physical_memory_set_dirty(s->vram_offset + offset);
    cpu_physical_memory_set_dirty(s->vram_offset + offset + 15);
}
