static bool net_tx_pkt_do_sw_fragmentation(struct NetTxPkt *pkt,
    NetClientState *nc)
{
    struct iovec fragment[NET_MAX_FRAG_SG_LIST];
    size_t fragment_len = 0;
    bool more_frags = false;

    /* some pointers for shorter code */
    void *l2_iov_base, *l3_iov_base;
    size_t l2_iov_len, l3_iov_len;
    int src_idx =  NET_TX_PKT_PL_START_FRAG, dst_idx;
    size_t src_offset = 0;
    size_t fragment_offset = 0;

    l2_iov_base = pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_base;
    l2_iov_len = pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_len;
    l3_iov_base = pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_base;
    l3_iov_len = pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_len;

    /* Copy headers */
    fragment[NET_TX_PKT_FRAGMENT_L2_HDR_POS].iov_base = l2_iov_base;
    fragment[NET_TX_PKT_FRAGMENT_L2_HDR_POS].iov_len = l2_iov_len;
    fragment[NET_TX_PKT_FRAGMENT_L3_HDR_POS].iov_base = l3_iov_base;
    fragment[NET_TX_PKT_FRAGMENT_L3_HDR_POS].iov_len = l3_iov_len;


    /* Put as much data as possible and send */
    do {
        fragment_len = net_tx_pkt_fetch_fragment(pkt, &src_idx, &src_offset,
            fragment, &dst_idx);

        more_frags = (fragment_offset + fragment_len < pkt->payload_len);

        eth_setup_ip4_fragmentation(l2_iov_base, l2_iov_len, l3_iov_base,
            l3_iov_len, fragment_len, fragment_offset, more_frags);

        eth_fix_ip4_checksum(l3_iov_base, l3_iov_len);

        net_tx_pkt_sendv(pkt, nc, fragment, dst_idx);

        fragment_offset += fragment_len;

    } while (fragment_len && more_frags);

    return true;
}
