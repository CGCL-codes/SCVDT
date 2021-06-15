static void xhci_process_commands(XHCIState *xhci)
{
    XHCITRB trb;
    TRBType type;
    XHCIEvent event = {ER_COMMAND_COMPLETE, CC_SUCCESS};
    dma_addr_t addr;
    unsigned int i, slotid = 0;

    DPRINTF("xhci_process_commands()\n");
    if (!xhci_running(xhci)) {
        DPRINTF("xhci_process_commands() called while xHC stopped or paused\n");
        return;
    }

    xhci->crcr_low |= CRCR_CRR;

    while ((type = xhci_ring_fetch(xhci, &xhci->cmd_ring, &trb, &addr))) {
        event.ptr = addr;
        switch (type) {
        case CR_ENABLE_SLOT:
            for (i = 0; i < xhci->numslots; i++) {
                if (!xhci->slots[i].enabled) {
                    break;
                }
            }
            if (i >= xhci->numslots) {
                DPRINTF("xhci: no device slots available\n");
                event.ccode = CC_NO_SLOTS_ERROR;
            } else {
                slotid = i+1;
                event.ccode = xhci_enable_slot(xhci, slotid);
            }
            break;
        case CR_DISABLE_SLOT:
            slotid = xhci_get_slot(xhci, &event, &trb);
            if (slotid) {
                event.ccode = xhci_disable_slot(xhci, slotid);
            }
            break;
        case CR_ADDRESS_DEVICE:
            slotid = xhci_get_slot(xhci, &event, &trb);
            if (slotid) {
                event.ccode = xhci_address_slot(xhci, slotid, trb.parameter,
                                                trb.control & TRB_CR_BSR);
            }
            break;
        case CR_CONFIGURE_ENDPOINT:
            slotid = xhci_get_slot(xhci, &event, &trb);
            if (slotid) {
                event.ccode = xhci_configure_slot(xhci, slotid, trb.parameter,
                                                  trb.control & TRB_CR_DC);
            }
            break;
        case CR_EVALUATE_CONTEXT:
            slotid = xhci_get_slot(xhci, &event, &trb);
            if (slotid) {
                event.ccode = xhci_evaluate_slot(xhci, slotid, trb.parameter);
            }
            break;
        case CR_STOP_ENDPOINT:
            slotid = xhci_get_slot(xhci, &event, &trb);
            if (slotid) {
                unsigned int epid = (trb.control >> TRB_CR_EPID_SHIFT)
                    & TRB_CR_EPID_MASK;
                event.ccode = xhci_stop_ep(xhci, slotid, epid);
            }
            break;
        case CR_RESET_ENDPOINT:
            slotid = xhci_get_slot(xhci, &event, &trb);
            if (slotid) {
                unsigned int epid = (trb.control >> TRB_CR_EPID_SHIFT)
                    & TRB_CR_EPID_MASK;
                event.ccode = xhci_reset_ep(xhci, slotid, epid);
            }
            break;
        case CR_SET_TR_DEQUEUE:
            slotid = xhci_get_slot(xhci, &event, &trb);
            if (slotid) {
                unsigned int epid = (trb.control >> TRB_CR_EPID_SHIFT)
                    & TRB_CR_EPID_MASK;
                unsigned int streamid = (trb.status >> 16) & 0xffff;
                event.ccode = xhci_set_ep_dequeue(xhci, slotid,
                                                  epid, streamid,
                                                  trb.parameter);
            }
            break;
        case CR_RESET_DEVICE:
            slotid = xhci_get_slot(xhci, &event, &trb);
            if (slotid) {
                event.ccode = xhci_reset_slot(xhci, slotid);
            }
            break;
        case CR_GET_PORT_BANDWIDTH:
            event.ccode = xhci_get_port_bandwidth(xhci, trb.parameter);
            break;
        case CR_VENDOR_VIA_CHALLENGE_RESPONSE:
            xhci_via_challenge(xhci, trb.parameter);
            break;
        case CR_VENDOR_NEC_FIRMWARE_REVISION:
            event.type = 48; /* NEC reply */
            event.length = 0x3025;
            break;
        case CR_VENDOR_NEC_CHALLENGE_RESPONSE:
        {
            uint32_t chi = trb.parameter >> 32;
            uint32_t clo = trb.parameter;
            uint32_t val = xhci_nec_challenge(chi, clo);
            event.length = val & 0xFFFF;
            event.epid = val >> 16;
            slotid = val >> 24;
            event.type = 48; /* NEC reply */
        }
        break;
        default:
            trace_usb_xhci_unimplemented("command", type);
            event.ccode = CC_TRB_ERROR;
            break;
        }
        event.slotid = slotid;
        xhci_event(xhci, &event, 0);
    }
}
