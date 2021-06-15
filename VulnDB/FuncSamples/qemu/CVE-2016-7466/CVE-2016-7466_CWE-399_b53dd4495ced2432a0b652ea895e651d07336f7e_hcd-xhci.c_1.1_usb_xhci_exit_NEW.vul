static void usb_xhci_exit(PCIDevice *dev)
{
    int i;
    XHCIState *xhci = XHCI(dev);

    trace_usb_xhci_exit();

    for (i = 0; i < xhci->numslots; i++) {
        xhci_disable_slot(xhci, i + 1);
    }

    if (xhci->mfwrap_timer) {
        timer_del(xhci->mfwrap_timer);
        timer_free(xhci->mfwrap_timer);
        xhci->mfwrap_timer = NULL;
    }

    memory_region_del_subregion(&xhci->mem, &xhci->mem_cap);
    memory_region_del_subregion(&xhci->mem, &xhci->mem_oper);
    memory_region_del_subregion(&xhci->mem, &xhci->mem_runtime);
    memory_region_del_subregion(&xhci->mem, &xhci->mem_doorbell);

    for (i = 0; i < xhci->numports; i++) {
        XHCIPort *port = &xhci->ports[i];
        memory_region_del_subregion(&xhci->mem, &port->mem);
    }

    /* destroy msix memory region */
    if (dev->msix_table && dev->msix_pba
        && dev->msix_entry_used) {
        msix_uninit(dev, &xhci->mem, &xhci->mem);
    }

    usb_bus_release(&xhci->bus);
}
