static int virtio_net_handle_mac(VirtIONet *n, uint8_t cmd,
                                 struct iovec *iov, unsigned int iov_cnt)
{
    struct virtio_net_ctrl_mac mac_data;
    size_t s;
    NetClientState *nc = qemu_get_queue(n->nic);

    if (cmd == VIRTIO_NET_CTRL_MAC_ADDR_SET) {
        if (iov_size(iov, iov_cnt) != sizeof(n->mac)) {
            return VIRTIO_NET_ERR;
        }
        s = iov_to_buf(iov, iov_cnt, 0, &n->mac, sizeof(n->mac));
        assert(s == sizeof(n->mac));
        qemu_format_nic_info_str(qemu_get_queue(n->nic), n->mac);
        rxfilter_notify(nc);

        return VIRTIO_NET_OK;
    }

    if (cmd != VIRTIO_NET_CTRL_MAC_TABLE_SET) {
        return VIRTIO_NET_ERR;
    }

    int in_use = 0;
    int first_multi = 0;
    uint8_t uni_overflow = 0;
    uint8_t multi_overflow = 0;
    uint8_t *macs = g_malloc0(MAC_TABLE_ENTRIES * ETH_ALEN);

    s = iov_to_buf(iov, iov_cnt, 0, &mac_data.entries,
                   sizeof(mac_data.entries));
    mac_data.entries = ldl_p(&mac_data.entries);
    if (s != sizeof(mac_data.entries)) {
        goto error;
    }
    iov_discard_front(&iov, &iov_cnt, s);

    if (mac_data.entries * ETH_ALEN > iov_size(iov, iov_cnt)) {
        goto error;
    }

    if (mac_data.entries <= MAC_TABLE_ENTRIES) {
        s = iov_to_buf(iov, iov_cnt, 0, macs,
                       mac_data.entries * ETH_ALEN);
        if (s != mac_data.entries * ETH_ALEN) {
            goto error;
        }
        in_use += mac_data.entries;
    } else {
        uni_overflow = 1;
    }

    iov_discard_front(&iov, &iov_cnt, mac_data.entries * ETH_ALEN);

    first_multi = in_use;

    s = iov_to_buf(iov, iov_cnt, 0, &mac_data.entries,
                   sizeof(mac_data.entries));
    mac_data.entries = ldl_p(&mac_data.entries);
    if (s != sizeof(mac_data.entries)) {
        goto error;
    }

    iov_discard_front(&iov, &iov_cnt, s);

    if (mac_data.entries * ETH_ALEN != iov_size(iov, iov_cnt)) {
        goto error;
    }

    if (mac_data.entries <= MAC_TABLE_ENTRIES - in_use) {
        s = iov_to_buf(iov, iov_cnt, 0, &macs[in_use * ETH_ALEN],
                       mac_data.entries * ETH_ALEN);
        if (s != mac_data.entries * ETH_ALEN) {
            goto error;
        }
        in_use += mac_data.entries;
    } else {
        multi_overflow = 1;
    }

    n->mac_table.in_use = in_use;
    n->mac_table.first_multi = first_multi;
    n->mac_table.uni_overflow = uni_overflow;
    n->mac_table.multi_overflow = multi_overflow;
    memcpy(n->mac_table.macs, macs, MAC_TABLE_ENTRIES * ETH_ALEN);
    g_free(macs);
    rxfilter_notify(nc);

    return VIRTIO_NET_OK;

error:
    g_free(macs);
    return VIRTIO_NET_ERR;
}
