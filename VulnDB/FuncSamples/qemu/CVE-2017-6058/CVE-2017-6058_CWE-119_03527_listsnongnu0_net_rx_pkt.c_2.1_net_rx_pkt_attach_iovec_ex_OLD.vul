void net_rx_pkt_attach_iovec_ex(struct NetRxPkt *pkt,
                                const struct iovec *iov, int iovcnt,
                                size_t iovoff, bool strip_vlan,
                                uint16_t vet)
{
    uint16_t tci = 0;
    uint16_t ploff = iovoff;
    assert(pkt);
    pkt->vlan_stripped = false;

    if (strip_vlan) {
        pkt->vlan_stripped = eth_strip_vlan_ex(iov, iovcnt, iovoff, vet,
                                               pkt->ehdr_buf,
                                               &ploff, &tci);
    }

    pkt->tci = tci;

    net_rx_pkt_pull_data(pkt, iov, iovcnt, ploff);
}
