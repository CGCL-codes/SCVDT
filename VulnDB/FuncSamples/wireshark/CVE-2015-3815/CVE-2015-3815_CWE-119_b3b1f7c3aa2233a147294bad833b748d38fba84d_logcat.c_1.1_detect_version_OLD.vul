static gint detect_version(wtap *wth, int *err, gchar **err_info)
{
    gint     bytes_read;
    guint16  payload_length;
    guint16  try_header_size;
    guint8  *buffer;
    gint64   file_offset;
    guint32  log_length;
    guint32  tag_length;
    guint16  tmp;

    file_offset = file_tell(wth->fh);

    bytes_read = file_read(&tmp, 2, wth->fh);
    if (bytes_read != 2) {
        *err = file_error(wth->fh, err_info);
        if (*err == 0 && bytes_read != 0)
            *err = WTAP_ERR_SHORT_READ;
        return -1;
    }
    payload_length = pletoh16(&tmp);

    bytes_read = file_read(&tmp, 2, wth->fh);
    if (bytes_read != 2) {
        *err = file_error(wth->fh, err_info);
        if (*err == 0 && bytes_read != 0)
            *err = WTAP_ERR_SHORT_READ;
        return -1;
    }
    try_header_size = pletoh16(&tmp);

    buffer = (guint8 *) g_malloc(5 * 4 + payload_length);
    bytes_read = file_read(buffer, 5 * 4 + payload_length, wth->fh);
    if (bytes_read != 5 * 4 + payload_length) {
        if (bytes_read != 4 * 4 + payload_length) {
            *err = file_error(wth->fh, err_info);
            if (*err == 0 && bytes_read != 0)
                *err = WTAP_ERR_SHORT_READ;
            g_free(buffer);
            return -1;
        }
    }

    if (try_header_size == 24) {
        tag_length = (guint32)strlen(buffer + 5 * 4 + 1) + 1;
        log_length = (guint32)strlen(buffer + 5 * 4 + 1 + tag_length) + 1;
        if (payload_length == 1 + tag_length + log_length) {
            g_free(buffer);
            return 2;
        }
    }

    tag_length = (guint32)strlen(buffer + 4 * 4 + 1) + 1;
    log_length = (guint32)strlen(buffer + 4 * 4 + 1 + tag_length) + 1;
    if (payload_length == 1 + tag_length + log_length) {
        if (file_seek(wth->fh, file_offset + 4 * 4 + 1 + tag_length + log_length, SEEK_SET, err) == -1) {
            g_free(buffer);
            return -1;
        }
        g_free(buffer);
        return 1;
    }

    g_free(buffer);
    return 0;
}
