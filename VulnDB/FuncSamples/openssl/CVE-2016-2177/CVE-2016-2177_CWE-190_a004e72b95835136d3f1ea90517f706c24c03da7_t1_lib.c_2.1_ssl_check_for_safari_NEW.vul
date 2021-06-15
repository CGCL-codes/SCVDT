static void ssl_check_for_safari(SSL *s, const unsigned char *data,
                                 const unsigned char *limit)
{
    unsigned short type, size;
    static const unsigned char kSafariExtensionsBlock[] = {
        0x00, 0x0a,             /* elliptic_curves extension */
        0x00, 0x08,             /* 8 bytes */
        0x00, 0x06,             /* 6 bytes of curve ids */
        0x00, 0x17,             /* P-256 */
        0x00, 0x18,             /* P-384 */
        0x00, 0x19,             /* P-521 */

        0x00, 0x0b,             /* ec_point_formats */
        0x00, 0x02,             /* 2 bytes */
        0x01,                   /* 1 point format */
        0x00,                   /* uncompressed */
    };

    /* The following is only present in TLS 1.2 */
    static const unsigned char kSafariTLS12ExtensionsBlock[] = {
        0x00, 0x0d,             /* signature_algorithms */
        0x00, 0x0c,             /* 12 bytes */
        0x00, 0x0a,             /* 10 bytes */
        0x05, 0x01,             /* SHA-384/RSA */
        0x04, 0x01,             /* SHA-256/RSA */
        0x02, 0x01,             /* SHA-1/RSA */
        0x04, 0x03,             /* SHA-256/ECDSA */
        0x02, 0x03,             /* SHA-1/ECDSA */
    };

    if (limit - data <= 2)
        return;
    data += 2;

    if (limit - data < 4)
        return;
    n2s(data, type);
    n2s(data, size);

    if (type != TLSEXT_TYPE_server_name)
        return;

    if (limit - data < size)
        return;
    data += size;

    if (TLS1_get_client_version(s) >= TLS1_2_VERSION) {
        const size_t len1 = sizeof(kSafariExtensionsBlock);
        const size_t len2 = sizeof(kSafariTLS12ExtensionsBlock);

        if (limit - data != (int)(len1 + len2))
            return;
        if (memcmp(data, kSafariExtensionsBlock, len1) != 0)
            return;
        if (memcmp(data + len1, kSafariTLS12ExtensionsBlock, len2) != 0)
            return;
    } else {
        const size_t len = sizeof(kSafariExtensionsBlock);

        if (limit - data != (int)(len))
            return;
        if (memcmp(data, kSafariExtensionsBlock, len) != 0)
            return;
    }

    s->s3->is_probably_safari = 1;
}
