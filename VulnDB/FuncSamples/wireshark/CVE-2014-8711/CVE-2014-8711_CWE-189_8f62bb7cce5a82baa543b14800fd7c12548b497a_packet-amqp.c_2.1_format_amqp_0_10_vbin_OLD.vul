static int
format_amqp_0_10_vbin(tvbuff_t *tvb,
                      guint offset, guint bound, guint length,
                      const char **value)
{
    guint bin_length;

    if (length == 1)
        bin_length = tvb_get_guint8(tvb, offset);
    else if (length == 2)
        bin_length = tvb_get_ntohs(tvb, offset);
    else if (length == 4)
        bin_length = tvb_get_ntohl(tvb, offset);
    else {
        *value = wmem_strdup_printf(wmem_packet_scope(), "Invalid vbin length size %d!", length);
        return length;
    }
    AMQP_INCREMENT(offset, length, bound);
    *value = tvb_bytes_to_ep_str(tvb, offset, bin_length);
    AMQP_INCREMENT(offset, bin_length, bound);
    return (bin_length + length);
}
