static int old_codec37(SANMVideoContext *ctx, int top,
                       int left, int width, int height)
{
    int stride = ctx->pitch;
    int i, j, k, t;
    int skip_run = 0;
    int compr, mvoff, seq, flags;
    uint32_t decoded_size;
    uint8_t *dst, *prev;

    compr        = bytestream2_get_byte(&ctx->gb);
    mvoff        = bytestream2_get_byte(&ctx->gb);
    seq          = bytestream2_get_le16(&ctx->gb);
    decoded_size = bytestream2_get_le32(&ctx->gb);
    bytestream2_skip(&ctx->gb, 4);
    flags        = bytestream2_get_byte(&ctx->gb);
    bytestream2_skip(&ctx->gb, 3);

    if (decoded_size > height * stride - left - top * stride) {
        decoded_size = height * stride - left - top * stride;
        av_log(ctx->avctx, AV_LOG_WARNING, "decoded size is too large\n");
    }

    ctx->rotate_code = 0;

    if (((seq & 1) || !(flags & 1)) && (compr && compr != 2))
        rotate_bufs(ctx, 1);

    dst  = ((uint8_t*)ctx->frm0) + left + top * stride;
    prev = ((uint8_t*)ctx->frm2) + left + top * stride;

    if (mvoff > 2) {
        av_log(ctx->avctx, AV_LOG_ERROR, "invalid motion base value %d\n", mvoff);
        return AVERROR_INVALIDDATA;
    }
    av_dlog(ctx->avctx, "compression %d\n", compr);
    switch (compr) {
    case 0:
        for (i = 0; i < height; i++) {
            bytestream2_get_buffer(&ctx->gb, dst, width);
            dst += stride;
        }
        memset(ctx->frm1, 0, ctx->height * stride);
        memset(ctx->frm2, 0, ctx->height * stride);
        break;
    case 2:
        if (rle_decode(ctx, dst, decoded_size))
            return AVERROR_INVALIDDATA;
        memset(ctx->frm1, 0, ctx->frm1_size);
        memset(ctx->frm2, 0, ctx->frm2_size);
        break;
    case 3:
    case 4:
        if (flags & 4) {
            for (j = 0; j < height; j += 4) {
                for (i = 0; i < width; i += 4) {
                    int code;
                    if (skip_run) {
                        skip_run--;
                        copy_block4(dst + i, prev + i, stride, stride, 4);
                        continue;
                    }
                    if (bytestream2_get_bytes_left(&ctx->gb) < 1)
                        return AVERROR_INVALIDDATA;
                    code = bytestream2_get_byteu(&ctx->gb);
                    switch (code) {
                    case 0xFF:
                        if (bytestream2_get_bytes_left(&ctx->gb) < 16)
                            return AVERROR_INVALIDDATA;
                        for (k = 0; k < 4; k++)
                            bytestream2_get_bufferu(&ctx->gb, dst + i + k * stride, 4);
                        break;
                    case 0xFE:
                        if (bytestream2_get_bytes_left(&ctx->gb) < 4)
                            return AVERROR_INVALIDDATA;
                        for (k = 0; k < 4; k++)
                            memset(dst + i + k * stride, bytestream2_get_byteu(&ctx->gb), 4);
                        break;
                    case 0xFD:
                        if (bytestream2_get_bytes_left(&ctx->gb) < 1)
                            return AVERROR_INVALIDDATA;
                        t = bytestream2_get_byteu(&ctx->gb);
                        for (k = 0; k < 4; k++)
                            memset(dst + i + k * stride, t, 4);
                        break;
                    default:
                        if (compr == 4 && !code) {
                            if (bytestream2_get_bytes_left(&ctx->gb) < 1)
                                return AVERROR_INVALIDDATA;
                            skip_run = bytestream2_get_byteu(&ctx->gb) + 1;
                            i -= 4;
                        } else {
                            int mx, my;

                            mx = c37_mv[(mvoff * 255 + code) * 2    ];
                            my = c37_mv[(mvoff * 255 + code) * 2 + 1];
                            codec37_mv(dst + i, prev + i + mx + my * stride,
                                       ctx->height, stride, i + mx, j + my);
                        }
                    }
                }
                dst  += stride * 4;
                prev += stride * 4;
            }
        } else {
            for (j = 0; j < height; j += 4) {
                for (i = 0; i < width; i += 4) {
                    int code;
                    if (skip_run) {
                        skip_run--;
                        copy_block4(dst + i, prev + i, stride, stride, 4);
                        continue;
                    }
                    code = bytestream2_get_byte(&ctx->gb);
                    if (code == 0xFF) {
                        if (bytestream2_get_bytes_left(&ctx->gb) < 16)
                            return AVERROR_INVALIDDATA;
                        for (k = 0; k < 4; k++)
                            bytestream2_get_bufferu(&ctx->gb, dst + i + k * stride, 4);
                    } else if (compr == 4 && !code) {
                        if (bytestream2_get_bytes_left(&ctx->gb) < 1)
                            return AVERROR_INVALIDDATA;
                        skip_run = bytestream2_get_byteu(&ctx->gb) + 1;
                        i -= 4;
                    } else {
                        int mx, my;

                        mx = c37_mv[(mvoff * 255 + code) * 2];
                        my = c37_mv[(mvoff * 255 + code) * 2 + 1];
                        codec37_mv(dst + i, prev + i + mx + my * stride,
                                   ctx->height, stride, i + mx, j + my);
                    }
                }
                dst  += stride * 4;
                prev += stride * 4;
            }
        }
        break;
    default:
        av_log(ctx->avctx, AV_LOG_ERROR,
               "subcodec 37 compression %d not implemented\n", compr);
        return AVERROR_PATCHWELCOME;
    }

    return 0;
}
