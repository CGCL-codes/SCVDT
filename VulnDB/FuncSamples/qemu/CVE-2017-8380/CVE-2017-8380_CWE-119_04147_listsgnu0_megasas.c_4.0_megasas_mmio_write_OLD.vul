static void megasas_mmio_write(void *opaque, hwaddr addr,
                               uint64_t val, unsigned size)
{
    MegasasState *s = opaque;
    PCIDevice *pci_dev = PCI_DEVICE(s);
    uint64_t frame_addr;
    uint32_t frame_count;
    int i;

    switch (addr) {
    case MFI_IDB:
        trace_megasas_mmio_writel("MFI_IDB", val);
        if (val & MFI_FWINIT_ABORT) {
            /* Abort all pending cmds */
            for (i = 0; i < s->fw_cmds; i++) {
                megasas_abort_command(&s->frames[i]);
            }
        }
        if (val & MFI_FWINIT_READY) {
            /* move to FW READY */
            megasas_soft_reset(s);
        }
        if (val & MFI_FWINIT_MFIMODE) {
            /* discard MFIs */
        }
        if (val & MFI_FWINIT_STOP_ADP) {
            /* Terminal error, stop processing */
            s->fw_state = MFI_FWSTATE_FAULT;
        }
        break;
    case MFI_OMSK:
        trace_megasas_mmio_writel("MFI_OMSK", val);
        s->intr_mask = val;
        if (!megasas_intr_enabled(s) &&
            !msi_enabled(pci_dev) &&
            !msix_enabled(pci_dev)) {
            trace_megasas_irq_lower();
            pci_irq_deassert(pci_dev);
        }
        if (megasas_intr_enabled(s)) {
            if (msix_enabled(pci_dev)) {
                trace_megasas_msix_enabled(0);
            } else if (msi_enabled(pci_dev)) {
                trace_megasas_msi_enabled(0);
            } else {
                trace_megasas_intr_enabled();
            }
        } else {
            trace_megasas_intr_disabled();
            megasas_soft_reset(s);
        }
        break;
    case MFI_ODCR0:
        trace_megasas_mmio_writel("MFI_ODCR0", val);
        s->doorbell = 0;
        if (megasas_intr_enabled(s)) {
            if (!msix_enabled(pci_dev) && !msi_enabled(pci_dev)) {
                trace_megasas_irq_lower();
                pci_irq_deassert(pci_dev);
            }
        }
        break;
    case MFI_IQPH:
        trace_megasas_mmio_writel("MFI_IQPH", val);
        /* Received high 32 bits of a 64 bit MFI frame address */
        s->frame_hi = val;
        break;
    case MFI_IQPL:
        trace_megasas_mmio_writel("MFI_IQPL", val);
        /* Received low 32 bits of a 64 bit MFI frame address */
        /* Fallthrough */
    case MFI_IQP:
        if (addr == MFI_IQP) {
            trace_megasas_mmio_writel("MFI_IQP", val);
            /* Received 64 bit MFI frame address */
            s->frame_hi = 0;
        }
        frame_addr = (val & ~0x1F);
        /* Add possible 64 bit offset */
        frame_addr |= ((uint64_t)s->frame_hi << 32);
        s->frame_hi = 0;
        frame_count = (val >> 1) & 0xF;
        megasas_handle_frame(s, frame_addr, frame_count);
        break;
    case MFI_SEQ:
        trace_megasas_mmio_writel("MFI_SEQ", val);
        /* Magic sequence to start ADP reset */
        if (adp_reset_seq[s->adp_reset] == val) {
            s->adp_reset++;
        } else {
            s->adp_reset = 0;
            s->diag = 0;
        }
        if (s->adp_reset == 6) {
            s->diag = MFI_DIAG_WRITE_ENABLE;
        }
        break;
    case MFI_DIAG:
        trace_megasas_mmio_writel("MFI_DIAG", val);
        /* ADP reset */
        if ((s->diag & MFI_DIAG_WRITE_ENABLE) &&
            (val & MFI_DIAG_RESET_ADP)) {
            s->diag |= MFI_DIAG_RESET_ADP;
            megasas_soft_reset(s);
            s->adp_reset = 0;
            s->diag = 0;
        }
        break;
    default:
        trace_megasas_mmio_invalid_writel(addr, val);
        break;
    }
}
