static int ohci_bus_start(OHCIState *ohci)
{
    trace_usb_ohci_start(ohci->name);

    /* Delay the first SOF event by one frame time as
     * linux driver is not ready to receive it and
     * can meet some race conditions
     */

    ohci_eof_timer(ohci);

    return 1;
}
