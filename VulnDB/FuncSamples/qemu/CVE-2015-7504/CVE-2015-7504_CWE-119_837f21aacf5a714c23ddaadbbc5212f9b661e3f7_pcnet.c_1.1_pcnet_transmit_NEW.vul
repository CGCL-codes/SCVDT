static void pcnet_transmit(PCNetState *s)
{
    hwaddr xmit_cxda = 0;
    int count = CSR_XMTRL(s)-1;
    int add_crc = 0;
    int bcnt;
    s->xmit_pos = -1;

    if (!CSR_TXON(s)) {
        s->csr[0] &= ~0x0008;
        return;
    }

    s->tx_busy = 1;

    txagain:
    if (pcnet_tdte_poll(s)) {
        struct pcnet_TMD tmd;

        TMDLOAD(&tmd, PHYSADDR(s,CSR_CXDA(s)));

#ifdef PCNET_DEBUG_TMD
        printf("  TMDLOAD 0x%08x\n", PHYSADDR(s,CSR_CXDA(s)));
        PRINT_TMD(&tmd);
#endif
        if (GET_FIELD(tmd.status, TMDS, STP)) {
            s->xmit_pos = 0;
            xmit_cxda = PHYSADDR(s,CSR_CXDA(s));
            if (BCR_SWSTYLE(s) != 1)
                add_crc = GET_FIELD(tmd.status, TMDS, ADDFCS);
        }
        if (s->lnkst == 0 &&
            (!CSR_LOOP(s) || (!CSR_INTL(s) && !BCR_TMAULOOP(s)))) {
            SET_FIELD(&tmd.misc, TMDM, LCAR, 1);
            SET_FIELD(&tmd.status, TMDS, ERR, 1);
            SET_FIELD(&tmd.status, TMDS, OWN, 0);
            s->csr[0] |= 0xa000; /* ERR | CERR */
            s->xmit_pos = -1;
            goto txdone;
        }

        if (s->xmit_pos < 0) {
            goto txdone;
        }

        bcnt = 4096 - GET_FIELD(tmd.length, TMDL, BCNT);

        /* if multi-tmd packet outsizes s->buffer then skip it silently.
         * Note: this is not what real hw does.
         * Last four bytes of s->buffer are used to store CRC FCS code.
         */
        if (s->xmit_pos + bcnt > sizeof(s->buffer) - 4) {
            s->xmit_pos = -1;
            goto txdone;
        }

        s->phys_mem_read(s->dma_opaque, PHYSADDR(s, tmd.tbadr),
                         s->buffer + s->xmit_pos, bcnt, CSR_BSWP(s));
        s->xmit_pos += bcnt;
        
        if (!GET_FIELD(tmd.status, TMDS, ENP)) {
            goto txdone;
        }

#ifdef PCNET_DEBUG
        printf("pcnet_transmit size=%d\n", s->xmit_pos);
#endif
        if (CSR_LOOP(s)) {
            if (BCR_SWSTYLE(s) == 1)
                add_crc = !GET_FIELD(tmd.status, TMDS, NOFCS);
            s->looptest = add_crc ? PCNET_LOOPTEST_CRC : PCNET_LOOPTEST_NOCRC;
            pcnet_receive(qemu_get_queue(s->nic), s->buffer, s->xmit_pos);
            s->looptest = 0;
        } else {
            if (s->nic) {
                qemu_send_packet(qemu_get_queue(s->nic), s->buffer,
                                 s->xmit_pos);
            }
        }

        s->csr[0] &= ~0x0008;   /* clear TDMD */
        s->csr[4] |= 0x0004;    /* set TXSTRT */
        s->xmit_pos = -1;

    txdone:
        SET_FIELD(&tmd.status, TMDS, OWN, 0);
        TMDSTORE(&tmd, PHYSADDR(s,CSR_CXDA(s)));
        if (!CSR_TOKINTD(s) || (CSR_LTINTEN(s) && GET_FIELD(tmd.status, TMDS, LTINT)))
            s->csr[0] |= 0x0200;    /* set TINT */

        if (CSR_XMTRC(s)<=1)
            CSR_XMTRC(s) = CSR_XMTRL(s);
        else
            CSR_XMTRC(s)--;
        if (count--)
            goto txagain;

    } else
    if (s->xmit_pos >= 0) {
        struct pcnet_TMD tmd;
        TMDLOAD(&tmd, xmit_cxda);
        SET_FIELD(&tmd.misc, TMDM, BUFF, 1);
        SET_FIELD(&tmd.misc, TMDM, UFLO, 1);
        SET_FIELD(&tmd.status, TMDS, ERR, 1);
        SET_FIELD(&tmd.status, TMDS, OWN, 0);
        TMDSTORE(&tmd, xmit_cxda);
        s->csr[0] |= 0x0200;    /* set TINT */
        if (!CSR_DXSUFLO(s)) {
            s->csr[0] &= ~0x0010;
        } else
        if (count--)
          goto txagain;
    }

    s->tx_busy = 0;
}
