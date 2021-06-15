static void vmxnet3_complete_packet(VMXNET3State *s, int qidx, uint32_t tx_ridx)
{
    struct Vmxnet3_TxCompDesc txcq_descr;
    PCIDevice *d = PCI_DEVICE(s);

    VMXNET3_RING_DUMP(VMW_RIPRN, "TXC", qidx, &s->txq_descr[qidx].comp_ring);

    txcq_descr.txdIdx = tx_ridx;
    txcq_descr.gen = vmxnet3_ring_curr_gen(&s->txq_descr[qidx].comp_ring);

    vmxnet3_ring_write_curr_cell(d, &s->txq_descr[qidx].comp_ring, &txcq_descr);

    /* Flush changes in TX descriptor before changing the counter value */
    smp_wmb();

    vmxnet3_inc_tx_completion_counter(s, qidx);
    vmxnet3_trigger_interrupt(s, s->txq_descr[qidx].intr_idx);
}
