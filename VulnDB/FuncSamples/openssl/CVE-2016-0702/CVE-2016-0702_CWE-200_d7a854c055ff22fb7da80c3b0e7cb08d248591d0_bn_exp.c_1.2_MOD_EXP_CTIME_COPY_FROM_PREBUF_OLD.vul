static int MOD_EXP_CTIME_COPY_FROM_PREBUF(BIGNUM *b, int top,
                                          unsigned char *buf, int idx,
                                          int width)
{
    size_t i, j;

    if (bn_wexpand(b, top) == NULL)
        return 0;

    for (i = 0, j = idx; i < top * sizeof b->d[0]; i++, j += width) {
        ((unsigned char *)b->d)[i] = buf[j];
    }

    b->top = top;
    bn_correct_top(b);
    return 1;
}
