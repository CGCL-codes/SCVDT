static bool ohci_eof_timer_needed(void *opaque)
{
    OHCIState *ohci = opaque;

    return timer_pending(ohci->eof_timer);
}
