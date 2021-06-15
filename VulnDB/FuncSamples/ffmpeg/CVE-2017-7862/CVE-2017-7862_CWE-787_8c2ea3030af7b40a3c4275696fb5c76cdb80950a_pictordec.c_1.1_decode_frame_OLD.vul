static int decode_frame(AVCodecContext *avctx,
                        void *data, int *got_frame,
                        AVPacket *avpkt)
{
    PicContext *s = avctx->priv_data;
    AVFrame *frame = data;
    uint32_t *palette;
    int bits_per_plane, bpp, etype, esize, npal, pos_after_pal;
    int i, x, y, plane, tmp, ret, val;

    bytestream2_init(&s->g, avpkt->data, avpkt->size);

    if (bytestream2_get_bytes_left(&s->g) < 11)
        return AVERROR_INVALIDDATA;

    if (bytestream2_get_le16u(&s->g) != 0x1234)
        return AVERROR_INVALIDDATA;

    s->width       = bytestream2_get_le16u(&s->g);
    s->height      = bytestream2_get_le16u(&s->g);
    bytestream2_skip(&s->g, 4);
    tmp            = bytestream2_get_byteu(&s->g);
    bits_per_plane = tmp & 0xF;
    s->nb_planes   = (tmp >> 4) + 1;
    bpp            = bits_per_plane * s->nb_planes;
    if (bits_per_plane > 8 || bpp < 1 || bpp > 32) {
        avpriv_request_sample(avctx, "Unsupported bit depth");
        return AVERROR_PATCHWELCOME;
    }

    if (bytestream2_peek_byte(&s->g) == 0xFF || bpp == 1 || bpp == 4 || bpp == 8) {
        bytestream2_skip(&s->g, 2);
        etype = bytestream2_get_le16(&s->g);
        esize = bytestream2_get_le16(&s->g);
        if (bytestream2_get_bytes_left(&s->g) < esize)
            return AVERROR_INVALIDDATA;
    } else {
        etype = -1;
        esize = 0;
    }

    avctx->pix_fmt = AV_PIX_FMT_PAL8;

    if (av_image_check_size(s->width, s->height, 0, avctx) < 0)
        return -1;
    if (s->width != avctx->width && s->height != avctx->height) {
        ret = ff_set_dimensions(avctx, s->width, s->height);
        if (ret < 0)
            return ret;
    }

    if ((ret = ff_get_buffer(avctx, frame, 0)) < 0)
        return ret;
    memset(frame->data[0], 0, s->height * frame->linesize[0]);
    frame->pict_type           = AV_PICTURE_TYPE_I;
    frame->palette_has_changed = 1;

    pos_after_pal = bytestream2_tell(&s->g) + esize;
    palette = (uint32_t*)frame->data[1];
    if (etype == 1 && esize > 1 && bytestream2_peek_byte(&s->g) < 6) {
        int idx = bytestream2_get_byte(&s->g);
        npal = 4;
        for (i = 0; i < npal; i++)
            palette[i] = ff_cga_palette[ cga_mode45_index[idx][i] ];
    } else if (etype == 2) {
        npal = FFMIN(esize, 16);
        for (i = 0; i < npal; i++) {
            int pal_idx = bytestream2_get_byte(&s->g);
            palette[i]  = ff_cga_palette[FFMIN(pal_idx, 15)];
        }
    } else if (etype == 3) {
        npal = FFMIN(esize, 16);
        for (i = 0; i < npal; i++) {
            int pal_idx = bytestream2_get_byte(&s->g);
            palette[i]  = ff_ega_palette[FFMIN(pal_idx, 63)];
        }
    } else if (etype == 4 || etype == 5) {
        npal = FFMIN(esize / 3, 256);
        for (i = 0; i < npal; i++) {
            palette[i] = bytestream2_get_be24(&s->g) << 2;
            palette[i] |= 0xFFU << 24 | palette[i] >> 6 & 0x30303;
        }
    } else {
        if (bpp == 1) {
            npal = 2;
            palette[0] = 0xFF000000;
            palette[1] = 0xFFFFFFFF;
        } else if (bpp == 2) {
            npal = 4;
            for (i = 0; i < npal; i++)
                palette[i] = ff_cga_palette[ cga_mode45_index[0][i] ];
        } else {
            npal = 16;
            memcpy(palette, ff_cga_palette, npal * 4);
        }
    }
    // fill remaining palette entries
    memset(palette + npal, 0, AVPALETTE_SIZE - npal * 4);
    // skip remaining palette bytes
    bytestream2_seek(&s->g, pos_after_pal, SEEK_SET);

    val = 0;
    y = s->height - 1;
    if (bytestream2_get_le16(&s->g)) {
        x = 0;
        plane = 0;
        while (bytestream2_get_bytes_left(&s->g) >= 6) {
            int stop_size, marker, t1, t2;

            t1        = bytestream2_get_bytes_left(&s->g);
            t2        = bytestream2_get_le16(&s->g);
            stop_size = t1 - FFMIN(t1, t2);
            // ignore uncompressed block size
            bytestream2_skip(&s->g, 2);
            marker    = bytestream2_get_byte(&s->g);

            while (plane < s->nb_planes &&
                   bytestream2_get_bytes_left(&s->g) > stop_size) {
                int run = 1;
                val = bytestream2_get_byte(&s->g);
                if (val == marker) {
                    run = bytestream2_get_byte(&s->g);
                    if (run == 0)
                        run = bytestream2_get_le16(&s->g);
                    val = bytestream2_get_byte(&s->g);
                }
                if (!bytestream2_get_bytes_left(&s->g))
                    break;

                if (bits_per_plane == 8) {
                    picmemset_8bpp(s, frame, val, run, &x, &y);
                    if (y < 0)
                        goto finish;
                } else {
                    picmemset(s, frame, val, run, &x, &y, &plane, bits_per_plane);
                }
            }
        }

        if (x < avctx->width) {
            int run = (y + 1) * avctx->width - x;
            if (bits_per_plane == 8)
                picmemset_8bpp(s, frame, val, run, &x, &y);
            else
                picmemset(s, frame, val, run / (8 / bits_per_plane), &x, &y, &plane, bits_per_plane);
        }
    } else {
        while (y >= 0 && bytestream2_get_bytes_left(&s->g) > 0) {
            memcpy(frame->data[0] + y * frame->linesize[0], s->g.buffer, FFMIN(avctx->width, bytestream2_get_bytes_left(&s->g)));
            bytestream2_skip(&s->g, avctx->width);
            y--;
        }
    }
finish:

    *got_frame      = 1;
    return avpkt->size;
}
