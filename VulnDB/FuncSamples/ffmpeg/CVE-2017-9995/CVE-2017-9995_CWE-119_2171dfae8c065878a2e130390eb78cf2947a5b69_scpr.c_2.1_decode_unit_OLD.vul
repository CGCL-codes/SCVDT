static int decode_unit(SCPRContext *s, PixelModel *pixel, unsigned step, unsigned *rval)
{
    GetByteContext *gb = &s->gb;
    RangeCoder *rc = &s->rc;
    unsigned totfr = pixel->total_freq;
    unsigned value, x = 0, cumfr = 0, cnt_x = 0;
    int i, j, ret, c, cnt_c;

    if ((ret = s->get_freq(rc, totfr, &value)) < 0)
        return ret;

    while (x < 16) {
        cnt_x = pixel->lookup[x];
        if (value >= cumfr + cnt_x)
            cumfr += cnt_x;
        else
            break;
        x++;
    }

    c = x * 16;
    cnt_c = 0;
    while (c < 256) {
        cnt_c = pixel->freq[c];
        if (value >= cumfr + cnt_c)
            cumfr += cnt_c;
        else
            break;
        c++;
    }

    if ((ret = s->decode(gb, rc, cumfr, cnt_c, totfr)) < 0)
        return ret;

    pixel->freq[c] = cnt_c + step;
    pixel->lookup[x] = cnt_x + step;
    totfr += step;
    if (totfr > BOT) {
        totfr = 0;
        for (i = 0; i < 256; i++) {
            unsigned nc = (pixel->freq[i] >> 1) + 1;
            pixel->freq[i] = nc;
            totfr += nc;
        }
        for (i = 0; i < 16; i++) {
            unsigned sum = 0;
            unsigned i16_17 = i << 4;
            for (j = 0; j < 16; j++)
                sum += pixel->freq[i16_17 + j];
            pixel->lookup[i] = sum;
        }
    }
    pixel->total_freq = totfr;

    *rval = c & s->cbits;

    return 0;
}
