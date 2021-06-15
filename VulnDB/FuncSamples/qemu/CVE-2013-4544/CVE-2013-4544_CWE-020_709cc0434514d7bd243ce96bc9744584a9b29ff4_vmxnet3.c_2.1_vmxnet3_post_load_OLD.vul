static int vmxnet3_post_load(void *opaque, int version_id)
{
    VMXNET3State *s = opaque;
    PCIDevice *d = PCI_DEVICE(s);

    vmxnet_tx_pkt_init(&s->tx_pkt, s->max_tx_frags, s->peer_has_vhdr);
    vmxnet_rx_pkt_init(&s->rx_pkt, s->peer_has_vhdr);

    if (s->msix_used) {
        if  (!vmxnet3_use_msix_vectors(s, VMXNET3_MAX_INTRS)) {
            VMW_WRPRN("Failed to re-use MSI-X vectors");
            msix_uninit(d, &s->msix_bar, &s->msix_bar);
            s->msix_used = false;
            return -1;
        }
    }

    return 0;
}
