static void vmxnet3_process_tx_queue(VMXNET3State *s, int qidx)
{
    struct Vmxnet3_TxDesc txd;
    uint32_t txd_idx;
    uint32_t data_len;
    hwaddr data_pa;

    for (;;) {
        if (!vmxnet3_pop_next_tx_descr(s, qidx, &txd, &txd_idx)) {
            break;
        }

        vmxnet3_dump_tx_descr(&txd);

        if (!s->skip_current_tx_pkt) {
            data_len = (txd.len > 0) ? txd.len : VMXNET3_MAX_TX_BUF_SIZE;
            data_pa = le64_to_cpu(txd.addr);

            if (!vmxnet_tx_pkt_add_raw_fragment(s->tx_pkt,
                                                data_pa,
                                                data_len)) {
                s->skip_current_tx_pkt = true;
            }
        }

        if (s->tx_sop) {
            vmxnet3_tx_retrieve_metadata(s, &txd);
            s->tx_sop = false;
        }

        if (txd.eop) {
            if (!s->skip_current_tx_pkt) {
                vmxnet_tx_pkt_parse(s->tx_pkt);

                if (s->needs_vlan) {
                    vmxnet_tx_pkt_setup_vlan_header(s->tx_pkt, s->tci);
                }

                vmxnet3_send_packet(s, qidx);
            } else {
                vmxnet3_on_tx_done_update_stats(s, qidx,
                                                VMXNET3_PKT_STATUS_ERROR);
            }

            vmxnet3_complete_packet(s, qidx, txd_idx);
            s->tx_sop = true;
            s->skip_current_tx_pkt = false;
            vmxnet_tx_pkt_reset(s->tx_pkt);
        }
    }
}
