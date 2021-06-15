static void vmxnet3_net_uninit(VMXNET3State *s)
{
    g_free(s->mcast_list);
    vmxnet_tx_pkt_reset(s->tx_pkt);
    vmxnet_tx_pkt_uninit(s->tx_pkt);
    vmxnet_rx_pkt_uninit(s->rx_pkt);
    qemu_del_nic(s->nic);
}
