static ssize_t drop_sync(QIOChannel *ioc, size_t size)
{
    ssize_t ret = 0;
    char small[1024];
    char *buffer;

    buffer = sizeof(small) < size ? small : g_malloc(MIN(65536, size));
    while (size > 0) {
        ssize_t count = read_sync(ioc, buffer, MIN(65536, size));

        if (count <= 0) {
            goto cleanup;
        }
        assert(count <= size);
        size -= count;
        ret += count;
    }

 cleanup:
    if (buffer != small) {
        g_free(buffer);
    }
    return ret;
}
