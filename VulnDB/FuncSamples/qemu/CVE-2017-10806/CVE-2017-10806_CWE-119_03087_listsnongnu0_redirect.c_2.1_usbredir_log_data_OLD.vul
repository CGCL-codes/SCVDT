static void usbredir_log_data(USBRedirDevice *dev, const char *desc,
    const uint8_t *data, int len)
{
    int i, j, n;

    if (dev->debug < usbredirparser_debug_data) {
        return;
    }

    for (i = 0; i < len; i += j) {
        char buf[128];

        n = sprintf(buf, "%s", desc);
        for (j = 0; j < 8 && i + j < len; j++) {
            n += sprintf(buf + n, " %02X", data[i + j]);
        }
        error_report("%s", buf);
    }
}
