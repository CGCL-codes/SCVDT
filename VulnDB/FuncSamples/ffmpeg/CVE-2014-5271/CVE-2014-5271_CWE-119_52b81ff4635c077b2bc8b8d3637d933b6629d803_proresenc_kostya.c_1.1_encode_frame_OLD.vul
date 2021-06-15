static int encode_frame(AVCodecContext *avctx, AVPacket *pkt,
                        const AVFrame *pic, int *got_packet)
{
    ProresContext *ctx = avctx->priv_data;
    uint8_t *orig_buf, *buf, *slice_hdr, *slice_sizes, *tmp;
    uint8_t *picture_size_pos;
    PutBitContext pb;
    int x, y, i, mb, q = 0;
    int sizes[4] = { 0 };
    int slice_hdr_size = 2 + 2 * (ctx->num_planes - 1);
    int frame_size, picture_size, slice_size;
    int pkt_size, ret;
    uint8_t frame_flags;

    *avctx->coded_frame           = *pic;
    avctx->coded_frame->pict_type = AV_PICTURE_TYPE_I;
    avctx->coded_frame->key_frame = 1;

    pkt_size = ctx->frame_size_upper_bound + FF_MIN_BUFFER_SIZE;

    if ((ret = ff_alloc_packet2(avctx, pkt, pkt_size)) < 0)
        return ret;

    orig_buf = pkt->data;

    // frame atom
    orig_buf += 4;                              // frame size
    bytestream_put_be32  (&orig_buf, FRAME_ID); // frame container ID
    buf = orig_buf;

    // frame header
    tmp = buf;
    buf += 2;                                   // frame header size will be stored here
    bytestream_put_be16  (&buf, 0);             // version 1
    bytestream_put_buffer(&buf, ctx->vendor, 4);
    bytestream_put_be16  (&buf, avctx->width);
    bytestream_put_be16  (&buf, avctx->height);

    frame_flags = ctx->chroma_factor << 6;
    if (avctx->flags & CODEC_FLAG_INTERLACED_DCT)
        frame_flags |= pic->top_field_first ? 0x04 : 0x08;
    bytestream_put_byte  (&buf, frame_flags);

    bytestream_put_byte  (&buf, 0);             // reserved
    bytestream_put_byte  (&buf, avctx->color_primaries);
    bytestream_put_byte  (&buf, avctx->color_trc);
    bytestream_put_byte  (&buf, avctx->colorspace);
    bytestream_put_byte  (&buf, 0x40 | (ctx->alpha_bits >> 3));
    bytestream_put_byte  (&buf, 0);             // reserved
    if (ctx->quant_sel != QUANT_MAT_DEFAULT) {
        bytestream_put_byte  (&buf, 0x03);      // matrix flags - both matrices are present
        // luma quantisation matrix
        for (i = 0; i < 64; i++)
            bytestream_put_byte(&buf, ctx->quant_mat[i]);
        // chroma quantisation matrix
        for (i = 0; i < 64; i++)
            bytestream_put_byte(&buf, ctx->quant_mat[i]);
    } else {
        bytestream_put_byte  (&buf, 0x00);      // matrix flags - default matrices are used
    }
    bytestream_put_be16  (&tmp, buf - orig_buf); // write back frame header size

    for (ctx->cur_picture_idx = 0;
         ctx->cur_picture_idx < ctx->pictures_per_frame;
         ctx->cur_picture_idx++) {
        // picture header
        picture_size_pos = buf + 1;
        bytestream_put_byte  (&buf, 0x40);          // picture header size (in bits)
        buf += 4;                                   // picture data size will be stored here
        bytestream_put_be16  (&buf, ctx->slices_per_picture);
        bytestream_put_byte  (&buf, av_log2(ctx->mbs_per_slice) << 4); // slice width and height in MBs

        // seek table - will be filled during slice encoding
        slice_sizes = buf;
        buf += ctx->slices_per_picture * 2;

        // slices
        if (!ctx->force_quant) {
            ret = avctx->execute2(avctx, find_quant_thread, NULL, NULL,
                                  ctx->mb_height);
            if (ret)
                return ret;
        }

        for (y = 0; y < ctx->mb_height; y++) {
            int mbs_per_slice = ctx->mbs_per_slice;
            for (x = mb = 0; x < ctx->mb_width; x += mbs_per_slice, mb++) {
                q = ctx->force_quant ? ctx->force_quant
                                     : ctx->slice_q[mb + y * ctx->slices_width];

                while (ctx->mb_width - x < mbs_per_slice)
                    mbs_per_slice >>= 1;

                bytestream_put_byte(&buf, slice_hdr_size << 3);
                slice_hdr = buf;
                buf += slice_hdr_size - 1;
                init_put_bits(&pb, buf, (pkt_size - (buf - orig_buf)) * 8);
                encode_slice(avctx, pic, &pb, sizes, x, y, q, mbs_per_slice);

                bytestream_put_byte(&slice_hdr, q);
                slice_size = slice_hdr_size + sizes[ctx->num_planes - 1];
                for (i = 0; i < ctx->num_planes - 1; i++) {
                    bytestream_put_be16(&slice_hdr, sizes[i]);
                    slice_size += sizes[i];
                }
                bytestream_put_be16(&slice_sizes, slice_size);
                buf += slice_size - slice_hdr_size;
            }
        }

        picture_size = buf - (picture_size_pos - 1);
        bytestream_put_be32(&picture_size_pos, picture_size);
    }

    orig_buf -= 8;
    frame_size = buf - orig_buf;
    bytestream_put_be32(&orig_buf, frame_size);

    pkt->size   = frame_size;
    pkt->flags |= AV_PKT_FLAG_KEY;
    *got_packet = 1;

    return 0;
}
