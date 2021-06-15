static int cbs_av1_read_uvlc(CodedBitstreamContext *ctx, GetBitContext *gbc,
                             const char *name, uint32_t *write_to,
                             uint32_t range_min, uint32_t range_max)
{
    uint32_t zeroes, bits_value, value;
    int position;

    if (ctx->trace_enable)
        position = get_bits_count(gbc);

    zeroes = 0;
    while (1) {
        if (get_bits_left(gbc) < 1) {
            av_log(ctx->log_ctx, AV_LOG_ERROR, "Invalid uvlc code at "
                   "%s: bitstream ended.\n", name);
            return AVERROR_INVALIDDATA;
        }

        if (get_bits1(gbc))
            break;
        ++zeroes;
    }

    if (zeroes >= 32) {
        value = MAX_UINT_BITS(32);
    } else {
        if (get_bits_left(gbc) < zeroes) {
            av_log(ctx->log_ctx, AV_LOG_ERROR, "Invalid uvlc code at "
                   "%s: bitstream ended.\n", name);
            return AVERROR_INVALIDDATA;
        }

        bits_value = get_bits_long(gbc, zeroes);
        value = bits_value + (UINT32_C(1) << zeroes) - 1;
    }

    if (ctx->trace_enable) {
        char bits[65];
        int i, j, k;

        if (zeroes >= 32) {
            while (zeroes > 32) {
                k = FFMIN(zeroes - 32, 32);
                for (i = 0; i < k; i++)
                    bits[i] = '0';
                bits[i] = 0;
                ff_cbs_trace_syntax_element(ctx, position, name,
                                            NULL, bits, 0);
                zeroes -= k;
                position += k;
            }
        }

        for (i = 0; i < zeroes; i++)
            bits[i] = '0';
        bits[i++] = '1';

        if (zeroes < 32) {
            for (j = 0; j < zeroes; j++)
                bits[i++] = (bits_value >> (zeroes - j - 1) & 1) ? '1' : '0';
        }

        bits[i] = 0;
        ff_cbs_trace_syntax_element(ctx, position, name,
                                    NULL, bits, value);
    }

    if (value < range_min || value > range_max) {
        av_log(ctx->log_ctx, AV_LOG_ERROR, "%s out of range: "
               "%"PRIu32", but must be in [%"PRIu32",%"PRIu32"].\n",
               name, value, range_min, range_max);
        return AVERROR_INVALIDDATA;
    }

    *write_to = value;
    return 0;
}
