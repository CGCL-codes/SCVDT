static bool cmd_smart(IDEState *s, uint8_t cmd)
{
    int n;

    if (s->hcyl != 0xc2 || s->lcyl != 0x4f) {
        goto abort_cmd;
    }

    if (!s->smart_enabled && s->feature != SMART_ENABLE) {
        goto abort_cmd;
    }

    switch (s->feature) {
    case SMART_DISABLE:
        s->smart_enabled = 0;
        return true;

    case SMART_ENABLE:
        s->smart_enabled = 1;
        return true;

    case SMART_ATTR_AUTOSAVE:
        switch (s->sector) {
        case 0x00:
            s->smart_autosave = 0;
            break;
        case 0xf1:
            s->smart_autosave = 1;
            break;
        default:
            goto abort_cmd;
        }
        return true;

    case SMART_STATUS:
        if (!s->smart_errors) {
            s->hcyl = 0xc2;
            s->lcyl = 0x4f;
        } else {
            s->hcyl = 0x2c;
            s->lcyl = 0xf4;
        }
        return true;

    case SMART_READ_THRESH:
        memset(s->io_buffer, 0, 0x200);
        s->io_buffer[0] = 0x01; /* smart struct version */

        for (n = 0; n < ARRAY_SIZE(smart_attributes); n++) {
            s->io_buffer[2 + 0 + (n * 12)] = smart_attributes[n][0];
            s->io_buffer[2 + 1 + (n * 12)] = smart_attributes[n][11];
        }

        /* checksum */
        for (n = 0; n < 511; n++) {
            s->io_buffer[511] += s->io_buffer[n];
        }
        s->io_buffer[511] = 0x100 - s->io_buffer[511];

        s->status = READY_STAT | SEEK_STAT;
        ide_transfer_start(s, s->io_buffer, 0x200, ide_transfer_stop);
        ide_set_irq(s->bus);
        return false;

    case SMART_READ_DATA:
        memset(s->io_buffer, 0, 0x200);
        s->io_buffer[0] = 0x01; /* smart struct version */

        for (n = 0; n < ARRAY_SIZE(smart_attributes); n++) {
            int i;
            for (i = 0; i < 11; i++) {
                s->io_buffer[2 + i + (n * 12)] = smart_attributes[n][i];
            }
        }

        s->io_buffer[362] = 0x02 | (s->smart_autosave ? 0x80 : 0x00);
        if (s->smart_selftest_count == 0) {
            s->io_buffer[363] = 0;
        } else {
            s->io_buffer[363] =
                s->smart_selftest_data[3 +
                           (s->smart_selftest_count - 1) *
                           24];
        }
        s->io_buffer[364] = 0x20;
        s->io_buffer[365] = 0x01;
        /* offline data collection capacity: execute + self-test*/
        s->io_buffer[367] = (1 << 4 | 1 << 3 | 1);
        s->io_buffer[368] = 0x03; /* smart capability (1) */
        s->io_buffer[369] = 0x00; /* smart capability (2) */
        s->io_buffer[370] = 0x01; /* error logging supported */
        s->io_buffer[372] = 0x02; /* minutes for poll short test */
        s->io_buffer[373] = 0x36; /* minutes for poll ext test */
        s->io_buffer[374] = 0x01; /* minutes for poll conveyance */

        for (n = 0; n < 511; n++) {
            s->io_buffer[511] += s->io_buffer[n];
        }
        s->io_buffer[511] = 0x100 - s->io_buffer[511];

        s->status = READY_STAT | SEEK_STAT;
        ide_transfer_start(s, s->io_buffer, 0x200, ide_transfer_stop);
        ide_set_irq(s->bus);
        return false;

    case SMART_READ_LOG:
        switch (s->sector) {
        case 0x01: /* summary smart error log */
            memset(s->io_buffer, 0, 0x200);
            s->io_buffer[0] = 0x01;
            s->io_buffer[1] = 0x00; /* no error entries */
            s->io_buffer[452] = s->smart_errors & 0xff;
            s->io_buffer[453] = (s->smart_errors & 0xff00) >> 8;

            for (n = 0; n < 511; n++) {
                s->io_buffer[511] += s->io_buffer[n];
            }
            s->io_buffer[511] = 0x100 - s->io_buffer[511];
            break;
        case 0x06: /* smart self test log */
            memset(s->io_buffer, 0, 0x200);
            s->io_buffer[0] = 0x01;
            if (s->smart_selftest_count == 0) {
                s->io_buffer[508] = 0;
            } else {
                s->io_buffer[508] = s->smart_selftest_count;
                for (n = 2; n < 506; n++)  {
                    s->io_buffer[n] = s->smart_selftest_data[n];
                }
            }

            for (n = 0; n < 511; n++) {
                s->io_buffer[511] += s->io_buffer[n];
            }
            s->io_buffer[511] = 0x100 - s->io_buffer[511];
            break;
        default:
            goto abort_cmd;
        }
        s->status = READY_STAT | SEEK_STAT;
        ide_transfer_start(s, s->io_buffer, 0x200, ide_transfer_stop);
        ide_set_irq(s->bus);
        return false;

    case SMART_EXECUTE_OFFLINE:
        switch (s->sector) {
        case 0: /* off-line routine */
        case 1: /* short self test */
        case 2: /* extended self test */
            s->smart_selftest_count++;
            if (s->smart_selftest_count > 21) {
                s->smart_selftest_count = 1;
            }
            n = 2 + (s->smart_selftest_count - 1) * 24;
            s->smart_selftest_data[n] = s->sector;
            s->smart_selftest_data[n + 1] = 0x00; /* OK and finished */
            s->smart_selftest_data[n + 2] = 0x34; /* hour count lsb */
            s->smart_selftest_data[n + 3] = 0x12; /* hour count msb */
            break;
        default:
            goto abort_cmd;
        }
        return true;
    }

abort_cmd:
    ide_abort_command(s);
    return true;
}
