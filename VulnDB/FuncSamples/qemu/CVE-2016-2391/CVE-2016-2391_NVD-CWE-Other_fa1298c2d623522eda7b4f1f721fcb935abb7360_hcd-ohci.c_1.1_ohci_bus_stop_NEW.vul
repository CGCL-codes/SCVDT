static void ohci_bus_stop(OHCIState *ohci)
{
    trace_usb_ohci_stop(ohci->name);
    timer_del(ohci->eof_timer);
}
