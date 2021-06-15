static int rndis_set_response(USBNetState *s,
                rndis_set_msg_type *buf, unsigned int length)
{
    rndis_set_cmplt_type *resp =
            rndis_queue_response(s, sizeof(rndis_set_cmplt_type));
    uint32_t bufoffs, buflen;
    int ret;

    if (!resp)
        return USB_RET_STALL;

    bufoffs = le32_to_cpu(buf->InformationBufferOffset) + 8;
    buflen = le32_to_cpu(buf->InformationBufferLength);
    if (bufoffs + buflen > length)
        return USB_RET_STALL;

    ret = ndis_set(s, le32_to_cpu(buf->OID),
                    bufoffs + (uint8_t *) buf, buflen);
    resp->MessageType = cpu_to_le32(RNDIS_SET_CMPLT);
    resp->RequestID = buf->RequestID; /* Still LE in msg buffer */
    resp->MessageLength = cpu_to_le32(sizeof(rndis_set_cmplt_type));
    if (ret < 0) {
        /* OID not supported */
        resp->Status = cpu_to_le32(RNDIS_STATUS_NOT_SUPPORTED);
        return 0;
    }
    resp->Status = cpu_to_le32(RNDIS_STATUS_SUCCESS);

    return 0;
}
