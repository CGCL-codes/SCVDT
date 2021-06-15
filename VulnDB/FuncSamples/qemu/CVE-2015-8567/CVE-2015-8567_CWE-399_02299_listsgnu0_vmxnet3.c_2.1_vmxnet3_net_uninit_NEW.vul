static void vmxnet3_net_uninit(VMXNET3State *s)
{
    g_free(s->mcast_list);
    vmxnet3_deactivate_device(s);
    qemu_del_nic(s->nic);
}
