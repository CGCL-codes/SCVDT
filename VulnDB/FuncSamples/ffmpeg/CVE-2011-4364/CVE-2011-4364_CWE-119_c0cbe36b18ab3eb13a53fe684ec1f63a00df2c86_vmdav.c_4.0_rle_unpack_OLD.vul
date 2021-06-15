static int rle_unpack(const unsigned char *src, unsigned char *dest,
    int src_len, int dest_len)
{
    const unsigned char *ps;
    unsigned char *pd;
    int i, l;
    unsigned char *dest_end = dest + dest_len;

    ps = src;
    pd = dest;
    if (src_len & 1)
        *pd++ = *ps++;

    src_len >>= 1;
    i = 0;
    do {
        l = *ps++;
        if (l & 0x80) {
            l = (l & 0x7F) * 2;
            if (pd + l > dest_end)
                return ps - src;
            memcpy(pd, ps, l);
            ps += l;
            pd += l;
        } else {
            if (pd + i > dest_end)
                return ps - src;
            for (i = 0; i < l; i++) {
                *pd++ = ps[0];
                *pd++ = ps[1];
            }
            ps += 2;
        }
        i += l;
    } while (i < src_len);

    return ps - src;
}
