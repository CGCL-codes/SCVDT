int ff_amf_get_field_value(const uint8_t *data, const uint8_t *data_end,
                           const uint8_t *name, uint8_t *dst, int dst_size)
{
    int namelen = strlen(name);
    int len;

    while (*data != AMF_DATA_TYPE_OBJECT && data < data_end) {
        len = ff_amf_tag_size(data, data_end);
        if (len < 0)
            len = data_end - data;
        data += len;
    }
    if (data_end - data < 3)
        return -1;
    data++;
    for (;;) {
        int size = bytestream_get_be16(&data);
        if (!size)
            break;
        if (size < 0 || size >= data_end - data)
            return -1;
        data += size;
        if (size == namelen && !memcmp(data-size, name, namelen)) {
            switch (*data++) {
            case AMF_DATA_TYPE_NUMBER:
                snprintf(dst, dst_size, "%g", av_int2double(AV_RB64(data)));
                break;
            case AMF_DATA_TYPE_BOOL:
                snprintf(dst, dst_size, "%s", *data ? "true" : "false");
                break;
            case AMF_DATA_TYPE_STRING:
                len = bytestream_get_be16(&data);
                av_strlcpy(dst, data, FFMIN(len+1, dst_size));
                break;
            default:
                return -1;
            }
            return 0;
        }
        len = ff_amf_tag_size(data, data_end);
        if (len < 0 || len >= data_end - data)
            return -1;
        data += len;
    }
    return -1;
}
