static int cbs_av1_read_uvlc(CodedBitstreamContext *ctx, GetBitContext *gbc,
                             const char *name, uint32_t *write_to,
                             uint32_t range_min, uint32_t range_max)
{
    uint32_t value;
    int position, zeroes, i, j;
    char bits[65];

    if (ctx->trace_enable)
        position = get_bits_count(gbc);

    zeroes = i = 0;
    while (1) {
        if (get_bits_left(gbc) < zeroes + 1) {
            av_log(ctx->log_ctx, AV_LOG_ERROR, "Invalid uvlc code at "
                   "%s: bitstream ended.\n", name);
            return AVERROR_INVALIDDATA;
        }

        if (get_bits1(gbc)) {
            bits[i++] = '1';
            break;
        } else {
            bits[i++] = '0';
            ++zeroes;
        }
    }

    if (zeroes >= 32) {
        value = MAX_UINT_BITS(32);
    } else {
        value = get_bits_long(gbc, zeroes);

        for (j = 0; j < zeroes; j++)
            bits[i++] = (value >> (zeroes - j - 1) & 1) ? '1' : '0';

        value += (1 << zeroes) - 1;
    }

    if (ctx->trace_enable) {
        bits[i] = 0;
        ff_cbs_trace_syntax_element(ctx, position, name, NULL,
                                    bits, value);
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
