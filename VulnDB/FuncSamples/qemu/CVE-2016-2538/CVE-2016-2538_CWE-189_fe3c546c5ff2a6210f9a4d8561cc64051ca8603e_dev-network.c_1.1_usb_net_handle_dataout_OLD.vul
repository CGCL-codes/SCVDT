static void usb_net_handle_dataout(USBNetState *s, USBPacket *p)
{
    int sz = sizeof(s->out_buf) - s->out_ptr;
    struct rndis_packet_msg_type *msg =
            (struct rndis_packet_msg_type *) s->out_buf;
    uint32_t len;

#ifdef TRAFFIC_DEBUG
    fprintf(stderr, "usbnet: data out len %zu\n", p->iov.size);
    iov_hexdump(p->iov.iov, p->iov.niov, stderr, "usbnet", p->iov.size);
#endif

    if (sz > p->iov.size) {
        sz = p->iov.size;
    }
    usb_packet_copy(p, &s->out_buf[s->out_ptr], sz);
    s->out_ptr += sz;

    if (!is_rndis(s)) {
        if (p->iov.size < 64) {
            qemu_send_packet(qemu_get_queue(s->nic), s->out_buf, s->out_ptr);
            s->out_ptr = 0;
        }
        return;
    }
    len = le32_to_cpu(msg->MessageLength);
    if (s->out_ptr < 8 || s->out_ptr < len) {
        return;
    }
    if (le32_to_cpu(msg->MessageType) == RNDIS_PACKET_MSG) {
        uint32_t offs = 8 + le32_to_cpu(msg->DataOffset);
        uint32_t size = le32_to_cpu(msg->DataLength);
        if (offs + size <= len)
            qemu_send_packet(qemu_get_queue(s->nic), s->out_buf + offs, size);
    }
    s->out_ptr -= len;
    memmove(s->out_buf, &s->out_buf[len], s->out_ptr);
}
