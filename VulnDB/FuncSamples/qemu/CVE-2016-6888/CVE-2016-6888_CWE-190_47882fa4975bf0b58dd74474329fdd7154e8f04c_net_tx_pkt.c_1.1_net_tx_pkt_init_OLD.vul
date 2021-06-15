void net_tx_pkt_init(struct NetTxPkt **pkt, PCIDevice *pci_dev,
    uint32_t max_frags, bool has_virt_hdr)
{
    struct NetTxPkt *p = g_malloc0(sizeof *p);

    p->pci_dev = pci_dev;

    p->vec = g_malloc((sizeof *p->vec) *
        (max_frags + NET_TX_PKT_PL_START_FRAG));

    p->raw = g_malloc((sizeof *p->raw) * max_frags);

    p->max_payload_frags = max_frags;
    p->max_raw_frags = max_frags;
    p->has_virt_hdr = has_virt_hdr;
    p->vec[NET_TX_PKT_VHDR_FRAG].iov_base = &p->virt_hdr;
    p->vec[NET_TX_PKT_VHDR_FRAG].iov_len =
        p->has_virt_hdr ? sizeof p->virt_hdr : 0;
    p->vec[NET_TX_PKT_L2HDR_FRAG].iov_base = &p->l2_hdr;
    p->vec[NET_TX_PKT_L3HDR_FRAG].iov_base = &p->l3_hdr;

    *pkt = p;
}
