static void ccid_on_apdu_from_guest(USBCCIDState *s, CCID_XferBlock *recv)
{
    uint32_t len;

    if (ccid_card_status(s) != ICC_STATUS_PRESENT_ACTIVE) {
        DPRINTF(s, 1,
                "usb-ccid: not sending apdu to client, no card connected\n");
        ccid_write_data_block_error(s, recv->hdr.bSlot, recv->hdr.bSeq);
        return;
    }
    len = le32_to_cpu(recv->hdr.dwLength);
    DPRINTF(s, 1, "%s: seq %d, len %d\n", __func__,
                recv->hdr.bSeq, len);
    ccid_add_pending_answer(s, (CCID_Header *)recv);
    if (s->card) {
        ccid_card_apdu_from_guest(s->card, recv->abData, len);
    } else {
        DPRINTF(s, D_WARN, "warning: discarded apdu\n");
    }
}
