static int decode_frame_common(AVCodecContext *avctx, PNGDecContext *s,
                               AVFrame *p, AVPacket *avpkt)
{
    AVDictionary *metadata  = NULL;
    uint32_t tag, length;
    int decode_next_dat = 0;
    int ret;

    for (;;) {
        length = bytestream2_get_bytes_left(&s->gb);
        if (length <= 0) {

            if (avctx->codec_id == AV_CODEC_ID_PNG &&
                avctx->skip_frame == AVDISCARD_ALL) {
                av_frame_set_metadata(p, metadata);
                return 0;
            }

            if (CONFIG_APNG_DECODER && avctx->codec_id == AV_CODEC_ID_APNG && length == 0) {
                if (!(s->state & PNG_IDAT))
                    return 0;
                else
                    goto exit_loop;
            }
            av_log(avctx, AV_LOG_ERROR, "%d bytes left\n", length);
            if (   s->state & PNG_ALLIMAGE
                && avctx->strict_std_compliance <= FF_COMPLIANCE_NORMAL)
                goto exit_loop;
            ret = AVERROR_INVALIDDATA;
            goto fail;
        }

        length = bytestream2_get_be32(&s->gb);
        if (length > 0x7fffffff || length > bytestream2_get_bytes_left(&s->gb)) {
            av_log(avctx, AV_LOG_ERROR, "chunk too big\n");
            ret = AVERROR_INVALIDDATA;
            goto fail;
        }
        tag = bytestream2_get_le32(&s->gb);
        if (avctx->debug & FF_DEBUG_STARTCODE)
            av_log(avctx, AV_LOG_DEBUG, "png: tag=%c%c%c%c length=%u\n",
                (tag & 0xff),
                ((tag >> 8) & 0xff),
                ((tag >> 16) & 0xff),
                ((tag >> 24) & 0xff), length);

        if (avctx->codec_id == AV_CODEC_ID_PNG &&
            avctx->skip_frame == AVDISCARD_ALL) {
            switch(tag) {
            case MKTAG('I', 'H', 'D', 'R'):
            case MKTAG('p', 'H', 'Y', 's'):
            case MKTAG('t', 'E', 'X', 't'):
            case MKTAG('I', 'D', 'A', 'T'):
            case MKTAG('t', 'R', 'N', 'S'):
                break;
            default:
                goto skip_tag;
            }
        }

        switch (tag) {
        case MKTAG('I', 'H', 'D', 'R'):
            if ((ret = decode_ihdr_chunk(avctx, s, length)) < 0)
                goto fail;
            break;
        case MKTAG('p', 'H', 'Y', 's'):
            if ((ret = decode_phys_chunk(avctx, s)) < 0)
                goto fail;
            break;
        case MKTAG('f', 'c', 'T', 'L'):
            if (!CONFIG_APNG_DECODER || avctx->codec_id != AV_CODEC_ID_APNG)
                goto skip_tag;
            if ((ret = decode_fctl_chunk(avctx, s, length)) < 0)
                goto fail;
            decode_next_dat = 1;
            break;
        case MKTAG('f', 'd', 'A', 'T'):
            if (!CONFIG_APNG_DECODER || avctx->codec_id != AV_CODEC_ID_APNG)
                goto skip_tag;
            if (!decode_next_dat) {
                ret = AVERROR_INVALIDDATA;
                goto fail;
            }
            bytestream2_get_be32(&s->gb);
            length -= 4;
            /* fallthrough */
        case MKTAG('I', 'D', 'A', 'T'):
            if (CONFIG_APNG_DECODER && avctx->codec_id == AV_CODEC_ID_APNG && !decode_next_dat)
                goto skip_tag;
            if ((ret = decode_idat_chunk(avctx, s, length, p)) < 0)
                goto fail;
            break;
        case MKTAG('P', 'L', 'T', 'E'):
            if (decode_plte_chunk(avctx, s, length) < 0)
                goto skip_tag;
            break;
        case MKTAG('t', 'R', 'N', 'S'):
            if (decode_trns_chunk(avctx, s, length) < 0)
                goto skip_tag;
            break;
        case MKTAG('t', 'E', 'X', 't'):
            if (decode_text_chunk(s, length, 0, &metadata) < 0)
                av_log(avctx, AV_LOG_WARNING, "Broken tEXt chunk\n");
            bytestream2_skip(&s->gb, length + 4);
            break;
        case MKTAG('z', 'T', 'X', 't'):
            if (decode_text_chunk(s, length, 1, &metadata) < 0)
                av_log(avctx, AV_LOG_WARNING, "Broken zTXt chunk\n");
            bytestream2_skip(&s->gb, length + 4);
            break;
        case MKTAG('s', 'T', 'E', 'R'): {
            int mode = bytestream2_get_byte(&s->gb);
            AVStereo3D *stereo3d = av_stereo3d_create_side_data(p);
            if (!stereo3d)
                goto fail;

            if (mode == 0 || mode == 1) {
                stereo3d->type  = AV_STEREO3D_SIDEBYSIDE;
                stereo3d->flags = mode ? 0 : AV_STEREO3D_FLAG_INVERT;
            } else {
                 av_log(avctx, AV_LOG_WARNING,
                        "Unknown value in sTER chunk (%d)\n", mode);
            }
            bytestream2_skip(&s->gb, 4); /* crc */
            break;
        }
        case MKTAG('I', 'E', 'N', 'D'):
            if (!(s->state & PNG_ALLIMAGE))
                av_log(avctx, AV_LOG_ERROR, "IEND without all image\n");
            if (!(s->state & (PNG_ALLIMAGE|PNG_IDAT))) {
                ret = AVERROR_INVALIDDATA;
                goto fail;
            }
            bytestream2_skip(&s->gb, 4); /* crc */
            goto exit_loop;
        default:
            /* skip tag */
skip_tag:
            bytestream2_skip(&s->gb, length + 4);
            break;
        }
    }
exit_loop:
    if (avctx->codec_id == AV_CODEC_ID_PNG &&
        avctx->skip_frame == AVDISCARD_ALL) {
        av_frame_set_metadata(p, metadata);
        return 0;
    }

    if (s->bits_per_pixel <= 4)
        handle_small_bpp(s, p);

    /* apply transparency if needed */
    if (s->has_trns && s->color_type != PNG_COLOR_TYPE_PALETTE) {
        size_t byte_depth = s->bit_depth > 8 ? 2 : 1;
        size_t raw_bpp = s->bpp - byte_depth;
        unsigned x, y;

        for (y = 0; y < s->height; ++y) {
            uint8_t *row = &s->image_buf[s->image_linesize * y];

            /* since we're updating in-place, we have to go from right to left */
            for (x = s->width; x > 0; --x) {
                uint8_t *pixel = &row[s->bpp * (x - 1)];
                memmove(pixel, &row[raw_bpp * (x - 1)], raw_bpp);

                if (!memcmp(pixel, s->transparent_color_be, raw_bpp)) {
                    memset(&pixel[raw_bpp], 0, byte_depth);
                } else {
                    memset(&pixel[raw_bpp], 0xff, byte_depth);
                }
            }
        }
    }

    /* handle P-frames only if a predecessor frame is available */
    if (s->last_picture.f->data[0]) {
        if (   !(avpkt->flags & AV_PKT_FLAG_KEY) && avctx->codec_tag != AV_RL32("MPNG")
            && s->last_picture.f->width == p->width
            && s->last_picture.f->height== p->height
            && s->last_picture.f->format== p->format
         ) {
            if (CONFIG_PNG_DECODER && avctx->codec_id != AV_CODEC_ID_APNG)
                handle_p_frame_png(s, p);
            else if (CONFIG_APNG_DECODER &&
                     avctx->codec_id == AV_CODEC_ID_APNG &&
                     (ret = handle_p_frame_apng(avctx, s, p)) < 0)
                goto fail;
        }
    }
    ff_thread_report_progress(&s->picture, INT_MAX, 0);
    ff_thread_report_progress(&s->previous_picture, INT_MAX, 0);

    av_frame_set_metadata(p, metadata);
    metadata   = NULL;
    return 0;

fail:
    av_dict_free(&metadata);
    ff_thread_report_progress(&s->picture, INT_MAX, 0);
    ff_thread_report_progress(&s->previous_picture, INT_MAX, 0);
    return ret;
}
