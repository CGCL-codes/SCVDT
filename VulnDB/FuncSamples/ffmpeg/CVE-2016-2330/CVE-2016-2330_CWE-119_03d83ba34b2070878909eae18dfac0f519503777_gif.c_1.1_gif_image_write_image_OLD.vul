static int gif_image_write_image(AVCodecContext *avctx,
                                 uint8_t **bytestream, uint8_t *end,
                                 const uint32_t *palette,
                                 const uint8_t *buf, const int linesize,
                                 AVPacket *pkt)
{
    GIFContext *s = avctx->priv_data;
    int len = 0, height = avctx->height, width = avctx->width, x, y;
    int x_start = 0, y_start = 0, trans = s->transparent_index;
    int honor_transparency = (s->flags & GF_TRANSDIFF) && s->last_frame;
    const uint8_t *ptr;

    /* Crop image */
    if ((s->flags & GF_OFFSETTING) && s->last_frame && !palette) {
        const uint8_t *ref = s->last_frame->data[0];
        const int ref_linesize = s->last_frame->linesize[0];
        int x_end = avctx->width  - 1,
            y_end = avctx->height - 1;

        /* skip common lines */
        while (y_start < y_end) {
            if (memcmp(ref + y_start*ref_linesize, buf + y_start*linesize, width))
                break;
            y_start++;
        }
        while (y_end > y_start) {
            if (memcmp(ref + y_end*ref_linesize, buf + y_end*linesize, width))
                break;
            y_end--;
        }
        height = y_end + 1 - y_start;

        /* skip common columns */
        while (x_start < x_end) {
            int same_column = 1;
            for (y = y_start; y <= y_end; y++) {
                if (ref[y*ref_linesize + x_start] != buf[y*linesize + x_start]) {
                    same_column = 0;
                    break;
                }
            }
            if (!same_column)
                break;
            x_start++;
        }
        while (x_end > x_start) {
            int same_column = 1;
            for (y = y_start; y <= y_end; y++) {
                if (ref[y*ref_linesize + x_end] != buf[y*linesize + x_end]) {
                    same_column = 0;
                    break;
                }
            }
            if (!same_column)
                break;
            x_end--;
        }
        width = x_end + 1 - x_start;

        av_log(avctx, AV_LOG_DEBUG,"%dx%d image at pos (%d;%d) [area:%dx%d]\n",
               width, height, x_start, y_start, avctx->width, avctx->height);
    }

    /* image block */
    bytestream_put_byte(bytestream, GIF_IMAGE_SEPARATOR);
    bytestream_put_le16(bytestream, x_start);
    bytestream_put_le16(bytestream, y_start);
    bytestream_put_le16(bytestream, width);
    bytestream_put_le16(bytestream, height);

    if (!palette) {
        bytestream_put_byte(bytestream, 0x00); /* flags */
    } else {
        unsigned i;
        bytestream_put_byte(bytestream, 1<<7 | 0x7); /* flags */
        for (i = 0; i < AVPALETTE_COUNT; i++) {
            const uint32_t v = palette[i];
            bytestream_put_be24(bytestream, v);
        }
    }

    if (honor_transparency && trans < 0) {
        trans = pick_palette_entry(buf + y_start*linesize + x_start,
                                   linesize, width, height);
        if (trans < 0) { // TODO, patch welcome
            av_log(avctx, AV_LOG_DEBUG, "No available color, can not use transparency\n");
        } else {
            uint8_t *pal_exdata = s->pal_exdata;
            if (!pal_exdata)
                pal_exdata = av_packet_new_side_data(pkt, AV_PKT_DATA_PALETTE, AVPALETTE_SIZE);
            if (!pal_exdata)
                return AVERROR(ENOMEM);
            memcpy(pal_exdata, s->palette, AVPALETTE_SIZE);
            pal_exdata[trans*4 + 3*!HAVE_BIGENDIAN] = 0x00;
        }
    }
    if (trans < 0)
        honor_transparency = 0;

    bytestream_put_byte(bytestream, 0x08);

    ff_lzw_encode_init(s->lzw, s->buf, 2 * width * height,
                       12, FF_LZW_GIF, put_bits);

    ptr = buf + y_start*linesize + x_start;
    if (honor_transparency) {
        const int ref_linesize = s->last_frame->linesize[0];
        const uint8_t *ref = s->last_frame->data[0] + y_start*ref_linesize + x_start;

        for (y = 0; y < height; y++) {
            memcpy(s->tmpl, ptr, width);
            for (x = 0; x < width; x++)
                if (ref[x] == ptr[x])
                    s->tmpl[x] = trans;
            len += ff_lzw_encode(s->lzw, s->tmpl, width);
            ptr += linesize;
            ref += ref_linesize;
        }
    } else {
        for (y = 0; y < height; y++) {
            len += ff_lzw_encode(s->lzw, ptr, width);
            ptr += linesize;
        }
    }
    len += ff_lzw_encode_flush(s->lzw, flush_put_bits);

    ptr = s->buf;
    while (len > 0) {
        int size = FFMIN(255, len);
        bytestream_put_byte(bytestream, size);
        if (end - *bytestream < size)
            return -1;
        bytestream_put_buffer(bytestream, ptr, size);
        ptr += size;
        len -= size;
    }
    bytestream_put_byte(bytestream, 0x00); /* end of image block */
    return 0;
}
