static int xhci_ring_chain_length(XHCIState *xhci, const XHCIRing *ring)
{
    PCIDevice *pci_dev = PCI_DEVICE(xhci);
    XHCITRB trb;
    int length = 0;
    dma_addr_t dequeue = ring->dequeue;
    bool ccs = ring->ccs;
    /* hack to bundle together the two/three TDs that make a setup transfer */
    bool control_td_set = 0;

    while (1) {
        TRBType type;
        pci_dma_read(pci_dev, dequeue, &trb, TRB_SIZE);
        le64_to_cpus(&trb.parameter);
        le32_to_cpus(&trb.status);
        le32_to_cpus(&trb.control);

        if ((trb.control & TRB_C) != ccs) {
            return -length;
        }

        type = TRB_TYPE(trb);

        if (type == TR_LINK) {
            dequeue = xhci_mask64(trb.parameter);
            if (trb.control & TRB_LK_TC) {
                ccs = !ccs;
            }
            continue;
        }

        length += 1;
        dequeue += TRB_SIZE;

        if (type == TR_SETUP) {
            control_td_set = 1;
        } else if (type == TR_STATUS) {
            control_td_set = 0;
        }

        if (!control_td_set && !(trb.control & TRB_TR_CH)) {
            return length;
        }
    }
}
