static int ape_decode_frame(AVCodecContext *avctx, void *data,
                            int *got_frame_ptr, AVPacket *avpkt)
{
    AVFrame *frame     = data;
    const uint8_t *buf = avpkt->data;
    APEContext *s = avctx->priv_data;
    uint8_t *sample8;
    int16_t *sample16;
    int32_t *sample24;
    int i, ch, ret;
    int blockstodecode;
    uint64_t decoded_buffer_size;

    /* this should never be negative, but bad things will happen if it is, so
       check it just to make sure. */
    av_assert0(s->samples >= 0);

    if(!s->samples){
        uint32_t nblocks, offset;
        int buf_size;

        if (!avpkt->size) {
            *got_frame_ptr = 0;
            return 0;
        }
        if (avpkt->size < 8) {
            av_log(avctx, AV_LOG_ERROR, "Packet is too small\n");
            return AVERROR_INVALIDDATA;
        }
        buf_size = avpkt->size & ~3;
        if (buf_size != avpkt->size) {
            av_log(avctx, AV_LOG_WARNING, "packet size is not a multiple of 4. "
                   "extra bytes at the end will be skipped.\n");
        }
        if (s->fileversion < 3950) // previous versions overread two bytes
            buf_size += 2;
        av_fast_padded_malloc(&s->data, &s->data_size, buf_size);
        if (!s->data)
            return AVERROR(ENOMEM);
        s->bdsp.bswap_buf((uint32_t *) s->data, (const uint32_t *) buf,
                          buf_size >> 2);
        memset(s->data + (buf_size & ~3), 0, buf_size & 3);
        s->ptr = s->data;
        s->data_end = s->data + buf_size;

        nblocks = bytestream_get_be32(&s->ptr);
        offset  = bytestream_get_be32(&s->ptr);
        if (s->fileversion >= 3900) {
            if (offset > 3) {
                av_log(avctx, AV_LOG_ERROR, "Incorrect offset passed\n");
                s->data = NULL;
                return AVERROR_INVALIDDATA;
            }
            if (s->data_end - s->ptr < offset) {
                av_log(avctx, AV_LOG_ERROR, "Packet is too small\n");
                return AVERROR_INVALIDDATA;
            }
            s->ptr += offset;
        } else {
            if ((ret = init_get_bits8(&s->gb, s->ptr, s->data_end - s->ptr)) < 0)
                return ret;
            if (s->fileversion > 3800)
                skip_bits_long(&s->gb, offset * 8);
            else
                skip_bits_long(&s->gb, offset);
        }

        if (!nblocks || nblocks > INT_MAX / 2 / sizeof(*s->decoded_buffer) - 8) {
            av_log(avctx, AV_LOG_ERROR, "Invalid sample count: %"PRIu32".\n",
                   nblocks);
            return AVERROR_INVALIDDATA;
        }

        /* Initialize the frame decoder */
        if (init_frame_decoder(s) < 0) {
            av_log(avctx, AV_LOG_ERROR, "Error reading frame header\n");
            return AVERROR_INVALIDDATA;
        }
        s->samples = nblocks;
    }

    if (!s->data) {
        *got_frame_ptr = 0;
        return avpkt->size;
    }

    blockstodecode = FFMIN(s->blocks_per_loop, s->samples);
    // for old files coefficients were not interleaved,
    // so we need to decode all of them at once
    if (s->fileversion < 3930)
        blockstodecode = s->samples;

    /* reallocate decoded sample buffer if needed */
    decoded_buffer_size = 2LL * FFALIGN(blockstodecode, 8) * sizeof(*s->decoded_buffer);
    av_assert0(decoded_buffer_size <= INT_MAX);
    av_fast_malloc(&s->decoded_buffer, &s->decoded_size, decoded_buffer_size);
    if (!s->decoded_buffer)
        return AVERROR(ENOMEM);
    memset(s->decoded_buffer, 0, s->decoded_size);
    s->decoded[0] = s->decoded_buffer;
    s->decoded[1] = s->decoded_buffer + FFALIGN(blockstodecode, 8);

    /* get output buffer */
    frame->nb_samples = blockstodecode;
    if ((ret = ff_get_buffer(avctx, frame, 0)) < 0)
        return ret;

    s->error=0;

    if ((s->channels == 1) || (s->frameflags & APE_FRAMECODE_PSEUDO_STEREO))
        ape_unpack_mono(s, blockstodecode);
    else
        ape_unpack_stereo(s, blockstodecode);
    emms_c();

    if (s->error) {
        s->samples=0;
        av_log(avctx, AV_LOG_ERROR, "Error decoding frame\n");
        return AVERROR_INVALIDDATA;
    }

    switch (s->bps) {
    case 8:
        for (ch = 0; ch < s->channels; ch++) {
            sample8 = (uint8_t *)frame->data[ch];
            for (i = 0; i < blockstodecode; i++)
                *sample8++ = (s->decoded[ch][i] + 0x80) & 0xff;
        }
        break;
    case 16:
        for (ch = 0; ch < s->channels; ch++) {
            sample16 = (int16_t *)frame->data[ch];
            for (i = 0; i < blockstodecode; i++)
                *sample16++ = s->decoded[ch][i];
        }
        break;
    case 24:
        for (ch = 0; ch < s->channels; ch++) {
            sample24 = (int32_t *)frame->data[ch];
            for (i = 0; i < blockstodecode; i++)
                *sample24++ = s->decoded[ch][i] << 8;
        }
        break;
    }

    s->samples -= blockstodecode;

    *got_frame_ptr = 1;

    return !s->samples ? avpkt->size : 0;
}
