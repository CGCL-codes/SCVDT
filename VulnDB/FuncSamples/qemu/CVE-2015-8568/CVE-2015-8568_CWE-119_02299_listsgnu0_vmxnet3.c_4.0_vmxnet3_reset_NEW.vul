static void vmxnet3_reset(VMXNET3State *s)
{
    VMW_CBPRN("Resetting vmxnet3...");

    vmxnet3_deactivate_device(s);
    vmxnet3_reset_interrupt_states(s);
    s->drv_shmem = 0;
    s->tx_sop = true;
    s->skip_current_tx_pkt = false;
}
