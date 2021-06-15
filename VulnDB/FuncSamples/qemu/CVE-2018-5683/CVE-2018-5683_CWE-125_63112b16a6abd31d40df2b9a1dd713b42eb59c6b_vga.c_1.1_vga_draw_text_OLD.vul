static void vga_draw_text(VGACommonState *s, int full_update)
{
    DisplaySurface *surface = qemu_console_surface(s->con);
    int cx, cy, cheight, cw, ch, cattr, height, width, ch_attr;
    int cx_min, cx_max, linesize, x_incr, line, line1;
    uint32_t offset, fgcol, bgcol, v, cursor_offset;
    uint8_t *d1, *d, *src, *dest, *cursor_ptr;
    const uint8_t *font_ptr, *font_base[2];
    int dup9, line_offset;
    uint32_t *palette;
    uint32_t *ch_attr_ptr;
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);

    /* compute font data address (in plane 2) */
    v = sr(s, VGA_SEQ_CHARACTER_MAP);
    offset = (((v >> 4) & 1) | ((v << 1) & 6)) * 8192 * 4 + 2;
    if (offset != s->font_offsets[0]) {
        s->font_offsets[0] = offset;
        full_update = 1;
    }
    font_base[0] = s->vram_ptr + offset;

    offset = (((v >> 5) & 1) | ((v >> 1) & 6)) * 8192 * 4 + 2;
    font_base[1] = s->vram_ptr + offset;
    if (offset != s->font_offsets[1]) {
        s->font_offsets[1] = offset;
        full_update = 1;
    }
    if (s->plane_updated & (1 << 2) || s->has_chain4_alias) {
        /* if the plane 2 was modified since the last display, it
           indicates the font may have been modified */
        s->plane_updated = 0;
        full_update = 1;
    }
    full_update |= update_basic_params(s);

    line_offset = s->line_offset;

    vga_get_text_resolution(s, &width, &height, &cw, &cheight);
    if ((height * width) <= 1) {
        /* better than nothing: exit if transient size is too small */
        return;
    }
    if ((height * width) > CH_ATTR_SIZE) {
        /* better than nothing: exit if transient size is too big */
        return;
    }

    if (width != s->last_width || height != s->last_height ||
        cw != s->last_cw || cheight != s->last_ch || s->last_depth) {
        s->last_scr_width = width * cw;
        s->last_scr_height = height * cheight;
        qemu_console_resize(s->con, s->last_scr_width, s->last_scr_height);
        surface = qemu_console_surface(s->con);
        dpy_text_resize(s->con, width, height);
        s->last_depth = 0;
        s->last_width = width;
        s->last_height = height;
        s->last_ch = cheight;
        s->last_cw = cw;
        full_update = 1;
    }
    full_update |= update_palette16(s);
    palette = s->last_palette;
    x_incr = cw * surface_bytes_per_pixel(surface);

    if (full_update) {
        s->full_update_text = 1;
    }
    if (s->full_update_gfx) {
        s->full_update_gfx = 0;
        full_update |= 1;
    }

    cursor_offset = ((s->cr[VGA_CRTC_CURSOR_HI] << 8) |
                     s->cr[VGA_CRTC_CURSOR_LO]) - s->start_addr;
    if (cursor_offset != s->cursor_offset ||
        s->cr[VGA_CRTC_CURSOR_START] != s->cursor_start ||
        s->cr[VGA_CRTC_CURSOR_END] != s->cursor_end) {
      /* if the cursor position changed, we update the old and new
         chars */
        if (s->cursor_offset < CH_ATTR_SIZE)
            s->last_ch_attr[s->cursor_offset] = -1;
        if (cursor_offset < CH_ATTR_SIZE)
            s->last_ch_attr[cursor_offset] = -1;
        s->cursor_offset = cursor_offset;
        s->cursor_start = s->cr[VGA_CRTC_CURSOR_START];
        s->cursor_end = s->cr[VGA_CRTC_CURSOR_END];
    }
    cursor_ptr = s->vram_ptr + (s->start_addr + cursor_offset) * 4;
    if (now >= s->cursor_blink_time) {
        s->cursor_blink_time = now + VGA_TEXT_CURSOR_PERIOD_MS / 2;
        s->cursor_visible_phase = !s->cursor_visible_phase;
    }

    dest = surface_data(surface);
    linesize = surface_stride(surface);
    ch_attr_ptr = s->last_ch_attr;
    line = 0;
    offset = s->start_addr * 4;
    for(cy = 0; cy < height; cy++) {
        d1 = dest;
        src = s->vram_ptr + offset;
        cx_min = width;
        cx_max = -1;
        for(cx = 0; cx < width; cx++) {
            ch_attr = *(uint16_t *)src;
            if (full_update || ch_attr != *ch_attr_ptr || src == cursor_ptr) {
                if (cx < cx_min)
                    cx_min = cx;
                if (cx > cx_max)
                    cx_max = cx;
                *ch_attr_ptr = ch_attr;
#ifdef HOST_WORDS_BIGENDIAN
                ch = ch_attr >> 8;
                cattr = ch_attr & 0xff;
#else
                ch = ch_attr & 0xff;
                cattr = ch_attr >> 8;
#endif
                font_ptr = font_base[(cattr >> 3) & 1];
                font_ptr += 32 * 4 * ch;
                bgcol = palette[cattr >> 4];
                fgcol = palette[cattr & 0x0f];
                if (cw == 16) {
                    vga_draw_glyph16(d1, linesize,
                                     font_ptr, cheight, fgcol, bgcol);
                } else if (cw != 9) {
                    vga_draw_glyph8(d1, linesize,
                                    font_ptr, cheight, fgcol, bgcol);
                } else {
                    dup9 = 0;
                    if (ch >= 0xb0 && ch <= 0xdf &&
                        (s->ar[VGA_ATC_MODE] & 0x04)) {
                        dup9 = 1;
                    }
                    vga_draw_glyph9(d1, linesize,
                                    font_ptr, cheight, fgcol, bgcol, dup9);
                }
                if (src == cursor_ptr &&
                    !(s->cr[VGA_CRTC_CURSOR_START] & 0x20) &&
                    s->cursor_visible_phase) {
                    int line_start, line_last, h;
                    /* draw the cursor */
                    line_start = s->cr[VGA_CRTC_CURSOR_START] & 0x1f;
                    line_last = s->cr[VGA_CRTC_CURSOR_END] & 0x1f;
                    /* XXX: check that */
                    if (line_last > cheight - 1)
                        line_last = cheight - 1;
                    if (line_last >= line_start && line_start < cheight) {
                        h = line_last - line_start + 1;
                        d = d1 + linesize * line_start;
                        if (cw == 16) {
                            vga_draw_glyph16(d, linesize,
                                             cursor_glyph, h, fgcol, bgcol);
                        } else if (cw != 9) {
                            vga_draw_glyph8(d, linesize,
                                            cursor_glyph, h, fgcol, bgcol);
                        } else {
                            vga_draw_glyph9(d, linesize,
                                            cursor_glyph, h, fgcol, bgcol, 1);
                        }
                    }
                }
            }
            d1 += x_incr;
            src += 4;
            ch_attr_ptr++;
        }
        if (cx_max != -1) {
            dpy_gfx_update(s->con, cx_min * cw, cy * cheight,
                           (cx_max - cx_min + 1) * cw, cheight);
        }
        dest += linesize * cheight;
        line1 = line + cheight;
        offset += line_offset;
        if (line < s->line_compare && line1 >= s->line_compare) {
            offset = 0;
        }
        line = line1;
    }
}
