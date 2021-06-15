int avpriv_ac3_parse_header(AC3HeaderInfo **phdr, const uint8_t *buf,
                            size_t size)
{
    GetBitContext gb;
    AC3HeaderInfo *hdr;
    int err;

    if (!*phdr)
        *phdr = av_mallocz(sizeof(AC3HeaderInfo));
    if (!*phdr)
        return AVERROR(ENOMEM);
    hdr = *phdr;

    err = init_get_bits8(&gb, buf, size);
    if (err < 0)
        return AVERROR_INVALIDDATA;
    err = ff_ac3_parse_header(&gb, hdr);
    if (err < 0)
        return AVERROR_INVALIDDATA;

    return get_bits_count(&gb);
}
