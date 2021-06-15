static int mxf_read_index_entry_array(AVIOContext *pb, MXFIndexTableSegment *segment)
{
    int i, length;

    segment->nb_index_entries = avio_rb32(pb);

    length = avio_rb32(pb);
    if(segment->nb_index_entries && length < 11)
        return AVERROR_INVALIDDATA;

    if (!(segment->temporal_offset_entries=av_calloc(segment->nb_index_entries, sizeof(*segment->temporal_offset_entries))) ||
        !(segment->flag_entries          = av_calloc(segment->nb_index_entries, sizeof(*segment->flag_entries))) ||
        !(segment->stream_offset_entries = av_calloc(segment->nb_index_entries, sizeof(*segment->stream_offset_entries)))) {
        av_freep(&segment->temporal_offset_entries);
        av_freep(&segment->flag_entries);
        return AVERROR(ENOMEM);
    }

    for (i = 0; i < segment->nb_index_entries; i++) {
        if(avio_feof(pb))
            return AVERROR_INVALIDDATA;
        segment->temporal_offset_entries[i] = avio_r8(pb);
        avio_r8(pb);                                        /* KeyFrameOffset */
        segment->flag_entries[i] = avio_r8(pb);
        segment->stream_offset_entries[i] = avio_rb64(pb);
        avio_skip(pb, length - 11);
    }
    return 0;
}
