static int megasas_map_dcmd(MegasasState *s, MegasasCmd *cmd)
{
    dma_addr_t iov_pa, iov_size;

    cmd->flags = le16_to_cpu(cmd->frame->header.flags);
    if (!cmd->frame->header.sge_count) {
        trace_megasas_dcmd_zero_sge(cmd->index);
        cmd->iov_size = 0;
        return 0;
    } else if (cmd->frame->header.sge_count > 1) {
        trace_megasas_dcmd_invalid_sge(cmd->index,
                                       cmd->frame->header.sge_count);
        cmd->iov_size = 0;
        return -1;
    }
    iov_pa = megasas_sgl_get_addr(cmd, &cmd->frame->dcmd.sgl);
    iov_size = megasas_sgl_get_len(cmd, &cmd->frame->dcmd.sgl);
    pci_dma_sglist_init(&cmd->qsg, PCI_DEVICE(s), 1);
    qemu_sglist_add(&cmd->qsg, iov_pa, iov_size);
    cmd->iov_size = iov_size;
    return cmd->iov_size;
}
