static int ehci_process_itd(EHCIState *ehci,
                            EHCIitd *itd,
                            uint32_t addr)
{
    USBDevice *dev;
    USBEndpoint *ep;
    uint32_t i, len, pid, dir, devaddr, endp;
    uint32_t pg, off, ptr1, ptr2, max, mult;

    ehci->periodic_sched_active = PERIODIC_ACTIVE;

    dir =(itd->bufptr[1] & ITD_BUFPTR_DIRECTION);
    devaddr = get_field(itd->bufptr[0], ITD_BUFPTR_DEVADDR);
    endp = get_field(itd->bufptr[0], ITD_BUFPTR_EP);
    max = get_field(itd->bufptr[1], ITD_BUFPTR_MAXPKT);
    mult = get_field(itd->bufptr[2], ITD_BUFPTR_MULT);

    for(i = 0; i < 8; i++) {
        if (itd->transact[i] & ITD_XACT_ACTIVE) {
            pg   = get_field(itd->transact[i], ITD_XACT_PGSEL);
            off  = itd->transact[i] & ITD_XACT_OFFSET_MASK;
            len  = get_field(itd->transact[i], ITD_XACT_LENGTH);

            if (len > max * mult) {
                len = max * mult;
            }
            if (len > BUFF_SIZE || pg > 6) {
                return -1;
            }

            ptr1 = (itd->bufptr[pg] & ITD_BUFPTR_MASK);
            qemu_sglist_init(&ehci->isgl, ehci->device, 2, ehci->as);
            if (off + len > 4096) {
                /* transfer crosses page border */
                if (pg == 6) {
                    qemu_sglist_destroy(&ehci->isgl);
                    return -1;  /* avoid page pg + 1 */
                }
                ptr2 = (itd->bufptr[pg + 1] & ITD_BUFPTR_MASK);
                uint32_t len2 = off + len - 4096;
                uint32_t len1 = len - len2;
                qemu_sglist_add(&ehci->isgl, ptr1 + off, len1);
                qemu_sglist_add(&ehci->isgl, ptr2, len2);
            } else {
                qemu_sglist_add(&ehci->isgl, ptr1 + off, len);
            }

            pid = dir ? USB_TOKEN_IN : USB_TOKEN_OUT;

            dev = ehci_find_device(ehci, devaddr);
            ep = usb_ep_get(dev, pid, endp);
            if (ep && ep->type == USB_ENDPOINT_XFER_ISOC) {
                usb_packet_setup(&ehci->ipacket, pid, ep, 0, addr, false,
                                 (itd->transact[i] & ITD_XACT_IOC) != 0);
                usb_packet_map(&ehci->ipacket, &ehci->isgl);
                usb_handle_packet(dev, &ehci->ipacket);
                usb_packet_unmap(&ehci->ipacket, &ehci->isgl);
            } else {
                DPRINTF("ISOCH: attempt to addess non-iso endpoint\n");
                ehci->ipacket.status = USB_RET_NAK;
                ehci->ipacket.actual_length = 0;
            }
            qemu_sglist_destroy(&ehci->isgl);

            switch (ehci->ipacket.status) {
            case USB_RET_SUCCESS:
                break;
            default:
                fprintf(stderr, "Unexpected iso usb result: %d\n",
                        ehci->ipacket.status);
                /* Fall through */
            case USB_RET_IOERROR:
            case USB_RET_NODEV:
                /* 3.3.2: XACTERR is only allowed on IN transactions */
                if (dir) {
                    itd->transact[i] |= ITD_XACT_XACTERR;
                    ehci_raise_irq(ehci, USBSTS_ERRINT);
                }
                break;
            case USB_RET_BABBLE:
                itd->transact[i] |= ITD_XACT_BABBLE;
                ehci_raise_irq(ehci, USBSTS_ERRINT);
                break;
            case USB_RET_NAK:
                /* no data for us, so do a zero-length transfer */
                ehci->ipacket.actual_length = 0;
                break;
            }
            if (!dir) {
                set_field(&itd->transact[i], len - ehci->ipacket.actual_length,
                          ITD_XACT_LENGTH); /* OUT */
            } else {
                set_field(&itd->transact[i], ehci->ipacket.actual_length,
                          ITD_XACT_LENGTH); /* IN */
            }
            if (itd->transact[i] & ITD_XACT_IOC) {
                ehci_raise_irq(ehci, USBSTS_INT);
            }
            itd->transact[i] &= ~ITD_XACT_ACTIVE;
        }
    }
    return 0;
}
