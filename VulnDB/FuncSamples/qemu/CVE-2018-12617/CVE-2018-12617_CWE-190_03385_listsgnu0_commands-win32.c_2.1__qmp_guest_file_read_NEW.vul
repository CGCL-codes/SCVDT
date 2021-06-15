GuestFileRead *qmp_guest_file_read(int64_t handle, bool has_count,
                                   int64_t count, Error **errp)
{
    GuestFileRead *read_data = NULL;
    guchar *buf;
    HANDLE fh;
    bool is_ok;
    DWORD read_count;
    GuestFileHandle *gfh = guest_file_handle_find(handle, errp);

    if (!gfh) {
        return NULL;
    }
    if (!has_count) {
        count = QGA_READ_COUNT_DEFAULT;
    } else if (count < 0 || count >= UINT32_MAX) {
        error_setg(errp, "value '%" PRId64
                   "' is invalid for argument count", count);
        return NULL;
    }

    fh = gfh->fh;
    buf = g_malloc0(count+1);
    is_ok = ReadFile(fh, buf, count, &read_count, NULL);
    if (!is_ok) {
        error_setg_win32(errp, GetLastError(), "failed to read file");
        slog("guest-file-read failed, handle %" PRId64, handle);
    } else {
        buf[read_count] = 0;
        read_data = g_new0(GuestFileRead, 1);
        read_data->count = (size_t)read_count;
        read_data->eof = read_count == 0;

        if (read_count != 0) {
            read_data->buf_b64 = g_base64_encode(buf, read_count);
        }
    }
    g_free(buf);

    return read_data;
}
