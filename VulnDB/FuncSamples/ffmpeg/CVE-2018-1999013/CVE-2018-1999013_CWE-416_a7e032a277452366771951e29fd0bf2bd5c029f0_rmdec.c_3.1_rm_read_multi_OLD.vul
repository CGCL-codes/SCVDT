static int rm_read_multi(AVFormatContext *s, AVIOContext *pb,
                         AVStream *st, char *mime)
{
    int number_of_streams = avio_rb16(pb);
    int number_of_mdpr;
    int i, ret;
    unsigned size2;
    for (i = 0; i<number_of_streams; i++)
        avio_rb16(pb);
    number_of_mdpr = avio_rb16(pb);
    if (number_of_mdpr != 1) {
        avpriv_request_sample(s, "MLTI with multiple (%d) MDPR", number_of_mdpr);
    }
    for (i = 0; i < number_of_mdpr; i++) {
        AVStream *st2;
        if (i > 0) {
            st2 = avformat_new_stream(s, NULL);
            if (!st2) {
                ret = AVERROR(ENOMEM);
                return ret;
            }
            st2->id = st->id + (i<<16);
            st2->codecpar->bit_rate = st->codecpar->bit_rate;
            st2->start_time = st->start_time;
            st2->duration   = st->duration;
            st2->codecpar->codec_type = AVMEDIA_TYPE_DATA;
            st2->priv_data = ff_rm_alloc_rmstream();
            if (!st2->priv_data)
                return AVERROR(ENOMEM);
        } else
            st2 = st;

        size2 = avio_rb32(pb);
        ret = ff_rm_read_mdpr_codecdata(s, s->pb, st2, st2->priv_data,
                                        size2, mime);
        if (ret < 0)
            return ret;
    }
    return 0;
}
