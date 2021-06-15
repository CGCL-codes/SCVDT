static void
net_rx_pkt_pull_data(struct NetRxPkt *pkt,
                        const struct iovec *iov, int iovcnt,
                        size_t ploff)
{
    if (pkt->vlan_stripped) {
        net_rx_pkt_iovec_realloc(pkt, iovcnt + 1);

        pkt->vec[0].iov_base = pkt->ehdr_buf;
        pkt->vec[0].iov_len = sizeof(pkt->ehdr_buf);

        pkt->tot_len =
            iov_size(iov, iovcnt) - ploff + sizeof(struct eth_header);

        pkt->vec_len = iov_copy(pkt->vec + 1, pkt->vec_len_total - 1,
                                iov, iovcnt, ploff, pkt->tot_len);
    } else {
        net_rx_pkt_iovec_realloc(pkt, iovcnt);

        pkt->tot_len = iov_size(iov, iovcnt) - ploff;
        pkt->vec_len = iov_copy(pkt->vec, pkt->vec_len_total,
                                iov, iovcnt, ploff, pkt->tot_len);
    }

    eth_get_protocols(pkt->vec, pkt->vec_len, &pkt->isip4, &pkt->isip6,
                      &pkt->isudp, &pkt->istcp,
                      &pkt->l3hdr_off, &pkt->l4hdr_off, &pkt->l5hdr_off,
                      &pkt->ip6hdr_info, &pkt->ip4hdr_info, &pkt->l4hdr_info);

    trace_net_rx_pkt_parsed(pkt->isip4, pkt->isip6, pkt->isudp, pkt->istcp,
                            pkt->l3hdr_off, pkt->l4hdr_off, pkt->l5hdr_off);
}
