static TRBType xhci_ring_fetch(XHCIState *xhci, XHCIRing *ring, XHCITRB *trb,
                               dma_addr_t *addr)
{
    PCIDevice *pci_dev = PCI_DEVICE(xhci);

    while (1) {
        TRBType type;
        pci_dma_read(pci_dev, ring->dequeue, trb, TRB_SIZE);
        trb->addr = ring->dequeue;
        trb->ccs = ring->ccs;
        le64_to_cpus(&trb->parameter);
        le32_to_cpus(&trb->status);
        le32_to_cpus(&trb->control);

        trace_usb_xhci_fetch_trb(ring->dequeue, trb_name(trb),
                                 trb->parameter, trb->status, trb->control);

        if ((trb->control & TRB_C) != ring->ccs) {
            return 0;
        }

        type = TRB_TYPE(*trb);

        if (type != TR_LINK) {
            if (addr) {
                *addr = ring->dequeue;
            }
            ring->dequeue += TRB_SIZE;
            return type;
        } else {
            ring->dequeue = xhci_mask64(trb->parameter);
            if (trb->control & TRB_LK_TC) {
                ring->ccs = !ring->ccs;
            }
        }
    }
}
