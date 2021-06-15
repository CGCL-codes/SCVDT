static int apng_encode_frame(AVCodecContext *avctx, const AVFrame *pict,
                             APNGFctlChunk *best_fctl_chunk, APNGFctlChunk *best_last_fctl_chunk)
{
    PNGEncContext *s = avctx->priv_data;
    int ret;
    unsigned int y;
    AVFrame* diffFrame;
    uint8_t bpp = (s->bits_per_pixel + 7) >> 3;
    uint8_t *original_bytestream, *original_bytestream_end;
    uint8_t *temp_bytestream = 0, *temp_bytestream_end;
    uint32_t best_sequence_number;
    uint8_t *best_bytestream;
    size_t best_bytestream_size = SIZE_MAX;
    APNGFctlChunk last_fctl_chunk = *best_last_fctl_chunk;
    APNGFctlChunk fctl_chunk = *best_fctl_chunk;

    if (avctx->frame_number == 0) {
        best_fctl_chunk->width = pict->width;
        best_fctl_chunk->height = pict->height;
        best_fctl_chunk->x_offset = 0;
        best_fctl_chunk->y_offset = 0;
        best_fctl_chunk->blend_op = APNG_BLEND_OP_SOURCE;
        return encode_frame(avctx, pict);
    }

    diffFrame = av_frame_alloc();
    if (!diffFrame)
        return AVERROR(ENOMEM);

    diffFrame->format = pict->format;
    diffFrame->width = pict->width;
    diffFrame->height = pict->height;
    if ((ret = av_frame_get_buffer(diffFrame, 32)) < 0)
        goto fail;

    original_bytestream = s->bytestream;
    original_bytestream_end = s->bytestream_end;

    temp_bytestream = av_malloc(original_bytestream_end - original_bytestream);
    temp_bytestream_end = temp_bytestream + (original_bytestream_end - original_bytestream);
    if (!temp_bytestream) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    for (last_fctl_chunk.dispose_op = 0; last_fctl_chunk.dispose_op < 3; ++last_fctl_chunk.dispose_op) {
        // 0: APNG_DISPOSE_OP_NONE
        // 1: APNG_DISPOSE_OP_BACKGROUND
        // 2: APNG_DISPOSE_OP_PREVIOUS

        for (fctl_chunk.blend_op = 0; fctl_chunk.blend_op < 2; ++fctl_chunk.blend_op) {
            // 0: APNG_BLEND_OP_SOURCE
            // 1: APNG_BLEND_OP_OVER

            uint32_t original_sequence_number = s->sequence_number, sequence_number;
            uint8_t *bytestream_start = s->bytestream;
            size_t bytestream_size;

            // Do disposal
            if (last_fctl_chunk.dispose_op != APNG_DISPOSE_OP_PREVIOUS) {
                memcpy(diffFrame->data[0], s->last_frame->data[0],
                       s->last_frame->linesize[0] * s->last_frame->height);

                if (last_fctl_chunk.dispose_op == APNG_DISPOSE_OP_BACKGROUND) {
                    for (y = last_fctl_chunk.y_offset; y < last_fctl_chunk.y_offset + last_fctl_chunk.height; ++y) {
                        size_t row_start = s->last_frame->linesize[0] * y + bpp * last_fctl_chunk.x_offset;
                        memset(diffFrame->data[0] + row_start, 0, bpp * last_fctl_chunk.width);
                    }
                }
            } else {
                if (!s->prev_frame)
                    continue;

                memcpy(diffFrame->data[0], s->prev_frame->data[0],
                       s->prev_frame->linesize[0] * s->prev_frame->height);
            }

            // Do inverse blending
            if (apng_do_inverse_blend(diffFrame, pict, &fctl_chunk, bpp) < 0)
                continue;

            // Do encoding
            ret = encode_frame(avctx, diffFrame);
            sequence_number = s->sequence_number;
            s->sequence_number = original_sequence_number;
            bytestream_size = s->bytestream - bytestream_start;
            s->bytestream = bytestream_start;
            if (ret < 0)
                goto fail;

            if (bytestream_size < best_bytestream_size) {
                *best_fctl_chunk = fctl_chunk;
                *best_last_fctl_chunk = last_fctl_chunk;

                best_sequence_number = sequence_number;
                best_bytestream = s->bytestream;
                best_bytestream_size = bytestream_size;

                if (best_bytestream == original_bytestream) {
                    s->bytestream = temp_bytestream;
                    s->bytestream_end = temp_bytestream_end;
                } else {
                    s->bytestream = original_bytestream;
                    s->bytestream_end = original_bytestream_end;
                }
            }
        }
    }

    s->sequence_number = best_sequence_number;
    s->bytestream = original_bytestream + best_bytestream_size;
    s->bytestream_end = original_bytestream_end;
    if (best_bytestream != original_bytestream)
        memcpy(original_bytestream, best_bytestream, best_bytestream_size);

    ret = 0;

fail:
    av_freep(&temp_bytestream);
    av_frame_free(&diffFrame);
    return ret;
}
