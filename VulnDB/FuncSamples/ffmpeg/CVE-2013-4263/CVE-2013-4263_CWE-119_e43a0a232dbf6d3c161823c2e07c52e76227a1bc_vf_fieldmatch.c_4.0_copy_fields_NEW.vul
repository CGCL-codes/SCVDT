static void copy_fields(const FieldMatchContext *fm, AVFrame *dst,
                        const AVFrame *src, int field)
{
    int plane;
    for (plane = 0; plane < 4 && src->data[plane] && src->linesize[plane]; plane++)
        av_image_copy_plane(dst->data[plane] + field*dst->linesize[plane], dst->linesize[plane] << 1,
                            src->data[plane] + field*src->linesize[plane], src->linesize[plane] << 1,
                            get_width(fm, src, plane), get_height(fm, src, plane) / 2);
}
