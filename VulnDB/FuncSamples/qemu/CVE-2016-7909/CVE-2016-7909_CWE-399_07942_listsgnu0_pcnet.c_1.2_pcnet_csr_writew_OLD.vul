static void pcnet_csr_writew(PCNetState *s, uint32_t rap, uint32_t new_value)
{
    uint16_t val = new_value;
#ifdef PCNET_DEBUG_CSR
    printf("pcnet_csr_writew rap=%d val=0x%04x\n", rap, val);
#endif
    switch (rap) {
    case 0:
        s->csr[0] &= ~(val & 0x7f00); /* Clear any interrupt flags */

        s->csr[0] = (s->csr[0] & ~0x0040) | (val & 0x0048);

        val = (val & 0x007f) | (s->csr[0] & 0x7f00);

        /* IFF STOP, STRT and INIT are set, clear STRT and INIT */
        if ((val&7) == 7)
          val &= ~3;

        if (!CSR_STOP(s) && (val & 4))
            pcnet_stop(s);

        if (!CSR_INIT(s) && (val & 1))
            pcnet_init(s);

        if (!CSR_STRT(s) && (val & 2))
            pcnet_start(s);

        if (CSR_TDMD(s))
            pcnet_transmit(s);

        return;
    case 1:
    case 2:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
    case 18: /* CRBAL */
    case 19: /* CRBAU */
    case 20: /* CXBAL */
    case 21: /* CXBAU */
    case 22: /* NRBAU */
    case 23: /* NRBAU */
    case 24:
    case 25:
    case 26:
    case 27:
    case 28:
    case 29:
    case 30:
    case 31:
    case 32:
    case 33:
    case 34:
    case 35:
    case 36:
    case 37:
    case 38:
    case 39:
    case 40: /* CRBC */
    case 41:
    case 42: /* CXBC */
    case 43:
    case 44:
    case 45:
    case 46: /* POLL */
    case 47: /* POLLINT */
    case 72:
    case 74:
    case 76: /* RCVRL */
    case 78: /* XMTRL */
    case 112:
       if (CSR_STOP(s) || CSR_SPND(s))
           break;
       return;
    case 3:
        break;
    case 4:
        s->csr[4] &= ~(val & 0x026a);
        val &= ~0x026a; val |= s->csr[4] & 0x026a;
        break;
    case 5:
        s->csr[5] &= ~(val & 0x0a90);
        val &= ~0x0a90; val |= s->csr[5] & 0x0a90;
        break;
    case 16:
        pcnet_csr_writew(s,1,val);
        return;
    case 17:
        pcnet_csr_writew(s,2,val);
        return;
    case 58:
        pcnet_bcr_writew(s,BCR_SWS,val);
        break;
    default:
        return;
    }
    s->csr[rap] = val;
}
