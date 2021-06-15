static int decode_zbuf(AVBPrint *bp, const uint8_t *data,
                       const uint8_t *data_end)
{
    z_stream zstream;
    unsigned char *buf;
    unsigned buf_size;
    int ret;

    zstream.zalloc = ff_png_zalloc;
    zstream.zfree  = ff_png_zfree;
    zstream.opaque = NULL;
    if (inflateInit(&zstream) != Z_OK)
        return AVERROR_EXTERNAL;
    zstream.next_in  = (unsigned char *)data;
    zstream.avail_in = data_end - data;
    av_bprint_init(bp, 0, -1);

    while (zstream.avail_in > 0) {
        av_bprint_get_buffer(bp, 1, &buf, &buf_size);
        if (!buf_size) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        zstream.next_out  = buf;
        zstream.avail_out = buf_size;
        ret = inflate(&zstream, Z_PARTIAL_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            ret = AVERROR_EXTERNAL;
            goto fail;
        }
        bp->len += zstream.next_out - buf;
        if (ret == Z_STREAM_END)
            break;
    }
    inflateEnd(&zstream);
    bp->str[bp->len] = 0;
    return 0;

fail:
    inflateEnd(&zstream);
    av_bprint_finalize(bp, NULL);
    return ret;
}
