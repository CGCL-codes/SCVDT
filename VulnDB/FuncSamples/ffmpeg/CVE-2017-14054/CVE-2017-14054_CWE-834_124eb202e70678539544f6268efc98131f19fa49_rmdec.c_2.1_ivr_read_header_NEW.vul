static int ivr_read_header(AVFormatContext *s)
{
    unsigned tag, type, len, tlen, value;
    int i, j, n, count, nb_streams = 0, ret;
    uint8_t key[256], val[256];
    AVIOContext *pb = s->pb;
    AVStream *st;
    int64_t pos, offset, temp;

    pos = avio_tell(pb);
    tag = avio_rl32(pb);
    if (tag == MKTAG('.','R','1','M')) {
        if (avio_rb16(pb) != 1)
            return AVERROR_INVALIDDATA;
        if (avio_r8(pb) != 1)
            return AVERROR_INVALIDDATA;
        len = avio_rb32(pb);
        avio_skip(pb, len);
        avio_skip(pb, 5);
        temp = avio_rb64(pb);
        while (!avio_feof(pb) && temp) {
            offset = temp;
            temp = avio_rb64(pb);
        }
        avio_skip(pb, offset - avio_tell(pb));
        if (avio_r8(pb) != 1)
            return AVERROR_INVALIDDATA;
        len = avio_rb32(pb);
        avio_skip(pb, len);
        if (avio_r8(pb) != 2)
            return AVERROR_INVALIDDATA;
        avio_skip(pb, 16);
        pos = avio_tell(pb);
        tag = avio_rl32(pb);
    }

    if (tag != MKTAG('.','R','E','C'))
        return AVERROR_INVALIDDATA;

    if (avio_r8(pb) != 0)
        return AVERROR_INVALIDDATA;
    count = avio_rb32(pb);
    for (i = 0; i < count; i++) {
        if (avio_feof(pb))
            return AVERROR_INVALIDDATA;

        type = avio_r8(pb);
        tlen = avio_rb32(pb);
        avio_get_str(pb, tlen, key, sizeof(key));
        len = avio_rb32(pb);
        if (type == 5) {
            avio_get_str(pb, len, val, sizeof(val));
            av_log(s, AV_LOG_DEBUG, "%s = '%s'\n", key, val);
        } else if (type == 4) {
            av_log(s, AV_LOG_DEBUG, "%s = '0x", key);
            for (j = 0; j < len; j++) {
                if (avio_feof(pb))
                    return AVERROR_INVALIDDATA;
                av_log(s, AV_LOG_DEBUG, "%X", avio_r8(pb));
            }
            av_log(s, AV_LOG_DEBUG, "'\n");
        } else if (len == 4 && type == 3 && !strncmp(key, "StreamCount", tlen)) {
            nb_streams = value = avio_rb32(pb);
        } else if (len == 4 && type == 3) {
            value = avio_rb32(pb);
            av_log(s, AV_LOG_DEBUG, "%s = %d\n", key, value);
        } else {
            av_log(s, AV_LOG_DEBUG, "Skipping unsupported key: %s\n", key);
            avio_skip(pb, len);
        }
    }

    for (n = 0; n < nb_streams; n++) {
        st = avformat_new_stream(s, NULL);
        if (!st)
            return AVERROR(ENOMEM);
        st->priv_data = ff_rm_alloc_rmstream();
        if (!st->priv_data)
            return AVERROR(ENOMEM);

        if (avio_r8(pb) != 1)
            return AVERROR_INVALIDDATA;

        count = avio_rb32(pb);
        for (i = 0; i < count; i++) {
            if (avio_feof(pb))
                return AVERROR_INVALIDDATA;

            type = avio_r8(pb);
            tlen  = avio_rb32(pb);
            avio_get_str(pb, tlen, key, sizeof(key));
            len  = avio_rb32(pb);
            if (type == 5) {
                avio_get_str(pb, len, val, sizeof(val));
                av_log(s, AV_LOG_DEBUG, "%s = '%s'\n", key, val);
            } else if (type == 4 && !strncmp(key, "OpaqueData", tlen)) {
                ret = ffio_ensure_seekback(pb, 4);
                if (ret < 0)
                    return ret;
                if (avio_rb32(pb) == MKBETAG('M', 'L', 'T', 'I')) {
                    ret = rm_read_multi(s, pb, st, NULL);
                } else {
                    avio_seek(pb, -4, SEEK_CUR);
                    ret = ff_rm_read_mdpr_codecdata(s, pb, st, st->priv_data, len, NULL);
                }

                if (ret < 0)
                    return ret;
            } else if (type == 4) {
                int j;

                av_log(s, AV_LOG_DEBUG, "%s = '0x", key);
                for (j = 0; j < len; j++)
                    av_log(s, AV_LOG_DEBUG, "%X", avio_r8(pb));
                av_log(s, AV_LOG_DEBUG, "'\n");
            } else if (len == 4 && type == 3 && !strncmp(key, "Duration", tlen)) {
                st->duration = avio_rb32(pb);
            } else if (len == 4 && type == 3) {
                value = avio_rb32(pb);
                av_log(s, AV_LOG_DEBUG, "%s = %d\n", key, value);
            } else {
                av_log(s, AV_LOG_DEBUG, "Skipping unsupported key: %s\n", key);
                avio_skip(pb, len);
            }
        }
    }

    if (avio_r8(pb) != 6)
        return AVERROR_INVALIDDATA;
    avio_skip(pb, 12);
    avio_skip(pb, avio_rb64(pb) + pos - avio_tell(s->pb));
    if (avio_r8(pb) != 8)
        return AVERROR_INVALIDDATA;
    avio_skip(pb, 8);

    return 0;
}
