static int ohci_service_ed_list(OHCIState *ohci, uint32_t head, int completion)
{
    struct ohci_ed ed;
    uint32_t next_ed;
    uint32_t cur;
    int active;

    active = 0;

    if (head == 0)
        return 0;

    for (cur = head; cur; cur = next_ed) {
        if (ohci_read_ed(ohci, cur, &ed)) {
            trace_usb_ohci_ed_read_error(cur);
            ohci_die(ohci);
            return 0;
        }

        next_ed = ed.next & OHCI_DPTR_MASK;

        if ((ed.head & OHCI_ED_H) || (ed.flags & OHCI_ED_K)) {
            uint32_t addr;
            /* Cancel pending packets for ED that have been paused.  */
            addr = ed.head & OHCI_DPTR_MASK;
            if (ohci->async_td && addr == ohci->async_td) {
                usb_cancel_packet(&ohci->usb_packet);
                ohci->async_td = 0;
                usb_device_ep_stopped(ohci->usb_packet.ep->dev,
                                      ohci->usb_packet.ep);
            }
            continue;
        }

        while ((ed.head & OHCI_DPTR_MASK) != ed.tail) {
            trace_usb_ohci_ed_pkt(cur, (ed.head & OHCI_ED_H) != 0,
                    (ed.head & OHCI_ED_C) != 0, ed.head & OHCI_DPTR_MASK,
                    ed.tail & OHCI_DPTR_MASK, ed.next & OHCI_DPTR_MASK);
            trace_usb_ohci_ed_pkt_flags(
                    OHCI_BM(ed.flags, ED_FA), OHCI_BM(ed.flags, ED_EN),
                    OHCI_BM(ed.flags, ED_D), (ed.flags & OHCI_ED_S)!= 0,
                    (ed.flags & OHCI_ED_K) != 0, (ed.flags & OHCI_ED_F) != 0,
                    OHCI_BM(ed.flags, ED_MPS));

            active = 1;

            if ((ed.flags & OHCI_ED_F) == 0) {
                if (ohci_service_td(ohci, &ed))
                    break;
            } else {
                /* Handle isochronous endpoints */
                if (ohci_service_iso_td(ohci, &ed, completion))
                    break;
            }
        }

        if (ohci_put_ed(ohci, cur, &ed)) {
            ohci_die(ohci);
            return 0;
        }
    }

    return active;
}
