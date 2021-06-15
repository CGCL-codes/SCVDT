static void usb_ohci_exit(PCIDevice *dev)
{
    OHCIPCIState *ohci = PCI_OHCI(dev);
    OHCIState *s = &ohci->state;

    trace_usb_ohci_exit(s->name);
    ohci_bus_stop(s);

    if (s->async_td) {
        usb_cancel_packet(&s->usb_packet);
        s->async_td = 0;
    }
    ohci_stop_endpoints(s);

    if (!ohci->masterbus) {
        usb_bus_release(&s->bus);
    }

    timer_del(s->eof_timer);
    timer_free(s->eof_timer);
}
