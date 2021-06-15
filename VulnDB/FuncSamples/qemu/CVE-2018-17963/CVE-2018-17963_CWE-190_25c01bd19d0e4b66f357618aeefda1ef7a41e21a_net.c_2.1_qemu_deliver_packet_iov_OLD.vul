ssize_t qemu_deliver_packet_iov(NetClientState *sender,
                                unsigned flags,
                                const struct iovec *iov,
                                int iovcnt,
                                void *opaque)
{
    NetClientState *nc = opaque;
    size_t size = iov_size(iov, iovcnt);
    int ret;

    if (size > INT_MAX) {
        return size;
    }

    if (nc->link_down) {
        return size;
    }

    if (nc->receive_disabled) {
        return 0;
    }

    if (nc->info->receive_iov && !(flags & QEMU_NET_PACKET_FLAG_RAW)) {
        ret = nc->info->receive_iov(nc, iov, iovcnt);
    } else {
        ret = nc_sendv_compat(nc, iov, iovcnt, flags);
    }

    if (ret == 0) {
        nc->receive_disabled = 1;
    }

    return ret;
}
