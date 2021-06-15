static int dnxhd_decode_header(DNXHDContext *ctx, AVFrame *frame,
                               const uint8_t *buf, int buf_size,
                               int first_field)
{
    int i, cid, ret;
    int old_bit_depth = ctx->bit_depth, bitdepth;
    uint64_t header_prefix;
    if (buf_size < 0x280) {
        av_log(ctx->avctx, AV_LOG_ERROR,
               "buffer too small (%d < 640).\n", buf_size);
        return AVERROR_INVALIDDATA;
    }

    header_prefix = ff_dnxhd_parse_header_prefix(buf);
    if (header_prefix == 0) {
        av_log(ctx->avctx, AV_LOG_ERROR,
               "unknown header 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
               buf[0], buf[1], buf[2], buf[3], buf[4]);
        return AVERROR_INVALIDDATA;
    }
    if (buf[5] & 2) { /* interlaced */
        ctx->cur_field = buf[5] & 1;
        frame->interlaced_frame = 1;
        frame->top_field_first  = first_field ^ ctx->cur_field;
        av_log(ctx->avctx, AV_LOG_DEBUG,
               "interlaced %d, cur field %d\n", buf[5] & 3, ctx->cur_field);
    } else {
        ctx->cur_field = 0;
    }
    ctx->mbaff = (buf[0x6] >> 5) & 1;

    ctx->height = AV_RB16(buf + 0x18);
    ctx->width  = AV_RB16(buf + 0x1a);

    switch(buf[0x21] >> 5) {
    case 1: bitdepth = 8; break;
    case 2: bitdepth = 10; break;
    case 3: bitdepth = 12; break;
    default:
        av_log(ctx->avctx, AV_LOG_ERROR,
               "Unknown bitdepth indicator (%d)\n", buf[0x21] >> 5);
        return AVERROR_INVALIDDATA;
    }

    cid = AV_RB32(buf + 0x28);

    ctx->avctx->profile = dnxhd_get_profile(cid);

    if ((ret = dnxhd_init_vlc(ctx, cid, bitdepth)) < 0)
        return ret;
    if (ctx->mbaff && ctx->cid_table->cid != 1260)
        av_log(ctx->avctx, AV_LOG_WARNING,
               "Adaptive MB interlace flag in an unsupported profile.\n");

    ctx->act = buf[0x2C] & 7;
    if (ctx->act && ctx->cid_table->cid != 1256 && ctx->cid_table->cid != 1270)
        av_log(ctx->avctx, AV_LOG_WARNING,
               "Adaptive color transform in an unsupported profile.\n");

    ctx->is_444 = (buf[0x2C] >> 6) & 1;
    if (ctx->is_444) {
        if (bitdepth == 8) {
            avpriv_request_sample(ctx->avctx, "4:4:4 8 bits");
            return AVERROR_INVALIDDATA;
        } else if (bitdepth == 10) {
            ctx->decode_dct_block = dnxhd_decode_dct_block_10_444;
            ctx->pix_fmt = ctx->act ? AV_PIX_FMT_YUV444P10
                                    : AV_PIX_FMT_GBRP10;
        } else {
            ctx->decode_dct_block = dnxhd_decode_dct_block_12_444;
            ctx->pix_fmt = ctx->act ? AV_PIX_FMT_YUV444P12
                                    : AV_PIX_FMT_GBRP12;
        }
    } else if (bitdepth == 12) {
        ctx->decode_dct_block = dnxhd_decode_dct_block_12;
        ctx->pix_fmt = AV_PIX_FMT_YUV422P12;
    } else if (bitdepth == 10) {
        if (ctx->avctx->profile == FF_PROFILE_DNXHR_HQX)
            ctx->decode_dct_block = dnxhd_decode_dct_block_10_444;
        else
            ctx->decode_dct_block = dnxhd_decode_dct_block_10;
        ctx->pix_fmt = AV_PIX_FMT_YUV422P10;
    } else {
        ctx->decode_dct_block = dnxhd_decode_dct_block_8;
        ctx->pix_fmt = AV_PIX_FMT_YUV422P;
    }

    ctx->avctx->bits_per_raw_sample = ctx->bit_depth = bitdepth;
    if (ctx->bit_depth != old_bit_depth) {
        ff_blockdsp_init(&ctx->bdsp, ctx->avctx);
        ff_idctdsp_init(&ctx->idsp, ctx->avctx);
        ff_init_scantable(ctx->idsp.idct_permutation, &ctx->scantable,
                          ff_zigzag_direct);
    }

    // make sure profile size constraints are respected
    // DNx100 allows 1920->1440 and 1280->960 subsampling
    if (ctx->width != ctx->cid_table->width &&
        ctx->cid_table->width != DNXHD_VARIABLE) {
        av_reduce(&ctx->avctx->sample_aspect_ratio.num,
                  &ctx->avctx->sample_aspect_ratio.den,
                  ctx->width, ctx->cid_table->width, 255);
        ctx->width = ctx->cid_table->width;
    }

    if (buf_size < ctx->cid_table->coding_unit_size) {
        av_log(ctx->avctx, AV_LOG_ERROR, "incorrect frame size (%d < %u).\n",
               buf_size, ctx->cid_table->coding_unit_size);
        return AVERROR_INVALIDDATA;
    }

    ctx->mb_width  = (ctx->width + 15)>> 4;
    ctx->mb_height = AV_RB16(buf + 0x16c);

    if ((ctx->height + 15) >> 4 == ctx->mb_height && frame->interlaced_frame)
        ctx->height <<= 1;

    av_log(ctx->avctx, AV_LOG_VERBOSE, "%dx%d, 4:%s %d bits, MBAFF=%d ACT=%d\n",
           ctx->width, ctx->height, ctx->is_444 ? "4:4" : "2:2",
           ctx->bit_depth, ctx->mbaff, ctx->act);

    // Newer format supports variable mb_scan_index sizes
    if (ctx->mb_height > 68 && ff_dnxhd_check_header_prefix_hr(header_prefix)) {
        ctx->data_offset = 0x170 + (ctx->mb_height << 2);
    } else {
        if (ctx->mb_height > 68) {
            av_log(ctx->avctx, AV_LOG_ERROR,
                   "mb height too big: %d\n", ctx->mb_height);
            return AVERROR_INVALIDDATA;
        }
        ctx->data_offset = 0x280;
    }
    if ((ctx->mb_height << frame->interlaced_frame) > (ctx->height + 15) >> 4) {
        av_log(ctx->avctx, AV_LOG_ERROR,
                "mb height too big: %d\n", ctx->mb_height);
        return AVERROR_INVALIDDATA;
    }

    if (buf_size < ctx->data_offset) {
        av_log(ctx->avctx, AV_LOG_ERROR,
               "buffer too small (%d < %d).\n", buf_size, ctx->data_offset);
        return AVERROR_INVALIDDATA;
    }

    if (ctx->mb_height > FF_ARRAY_ELEMS(ctx->mb_scan_index)) {
        av_log(ctx->avctx, AV_LOG_ERROR,
               "mb_height too big (%d > %"SIZE_SPECIFIER").\n", ctx->mb_height, FF_ARRAY_ELEMS(ctx->mb_scan_index));
        return AVERROR_INVALIDDATA;
    }

    for (i = 0; i < ctx->mb_height; i++) {
        ctx->mb_scan_index[i] = AV_RB32(buf + 0x170 + (i << 2));
        ff_dlog(ctx->avctx, "mb scan index %d, pos %d: %"PRIu32"\n",
                i, 0x170 + (i << 2), ctx->mb_scan_index[i]);
        if (buf_size - ctx->data_offset < ctx->mb_scan_index[i]) {
            av_log(ctx->avctx, AV_LOG_ERROR,
                   "invalid mb scan index (%"PRIu32" vs %u).\n",
                   ctx->mb_scan_index[i], buf_size - ctx->data_offset);
            return AVERROR_INVALIDDATA;
        }
    }

    return 0;
}
