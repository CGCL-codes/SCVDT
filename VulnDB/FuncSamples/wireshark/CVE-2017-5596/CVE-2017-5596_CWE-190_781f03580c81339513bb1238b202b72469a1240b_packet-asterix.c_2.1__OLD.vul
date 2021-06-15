static guint8 asterix_fspec_len (tvbuff_t *tvb, guint offset)
{
    guint8 i;
    for (i = 0; (tvb_get_guint8 (tvb, offset + i) & 1) && i < tvb_reported_length (tvb) - offset; i++);
    return i + 1;
}
