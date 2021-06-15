static int protocol_client_msg(VncState *vs, uint8_t *data, size_t len)
{
    int i;
    uint16_t limit;
    VncDisplay *vd = vs->vd;

    if (data[0] > 3) {
        update_displaychangelistener(&vd->dcl, VNC_REFRESH_INTERVAL_BASE);
    }

    switch (data[0]) {
    case VNC_MSG_CLIENT_SET_PIXEL_FORMAT:
        if (len == 1)
            return 20;

        set_pixel_format(vs, read_u8(data, 4), read_u8(data, 5),
                         read_u8(data, 6), read_u8(data, 7),
                         read_u16(data, 8), read_u16(data, 10),
                         read_u16(data, 12), read_u8(data, 14),
                         read_u8(data, 15), read_u8(data, 16));
        break;
    case VNC_MSG_CLIENT_SET_ENCODINGS:
        if (len == 1)
            return 4;

        if (len == 4) {
            limit = read_u16(data, 2);
            if (limit > 0)
                return 4 + (limit * 4);
        } else
            limit = read_u16(data, 2);

        for (i = 0; i < limit; i++) {
            int32_t val = read_s32(data, 4 + (i * 4));
            memcpy(data + 4 + (i * 4), &val, sizeof(val));
        }

        set_encodings(vs, (int32_t *)(data + 4), limit);
        break;
    case VNC_MSG_CLIENT_FRAMEBUFFER_UPDATE_REQUEST:
        if (len == 1)
            return 10;

        framebuffer_update_request(vs,
                                   read_u8(data, 1), read_u16(data, 2), read_u16(data, 4),
                                   read_u16(data, 6), read_u16(data, 8));
        break;
    case VNC_MSG_CLIENT_KEY_EVENT:
        if (len == 1)
            return 8;

        key_event(vs, read_u8(data, 1), read_u32(data, 4));
        break;
    case VNC_MSG_CLIENT_POINTER_EVENT:
        if (len == 1)
            return 6;

        pointer_event(vs, read_u8(data, 1), read_u16(data, 2), read_u16(data, 4));
        break;
    case VNC_MSG_CLIENT_CUT_TEXT:
        if (len == 1) {
            return 8;
        }
        if (len == 8) {
            uint32_t dlen = read_u32(data, 4);
            if (dlen > (1 << 20)) {
                error_report("vnc: client_cut_text msg payload has %u bytes"
                             " which exceeds our limit of 1MB.", dlen);
                vnc_client_error(vs);
                break;
            }
            if (dlen > 0) {
                return 8 + dlen;
            }
        }

        client_cut_text(vs, read_u32(data, 4), data + 8);
        break;
    case VNC_MSG_CLIENT_QEMU:
        if (len == 1)
            return 2;

        switch (read_u8(data, 1)) {
        case VNC_MSG_CLIENT_QEMU_EXT_KEY_EVENT:
            if (len == 2)
                return 12;

            ext_key_event(vs, read_u16(data, 2),
                          read_u32(data, 4), read_u32(data, 8));
            break;
        case VNC_MSG_CLIENT_QEMU_AUDIO:
            if (len == 2)
                return 4;

            switch (read_u16 (data, 2)) {
            case VNC_MSG_CLIENT_QEMU_AUDIO_ENABLE:
                audio_add(vs);
                break;
            case VNC_MSG_CLIENT_QEMU_AUDIO_DISABLE:
                audio_del(vs);
                break;
            case VNC_MSG_CLIENT_QEMU_AUDIO_SET_FORMAT:
                if (len == 4)
                    return 10;
                switch (read_u8(data, 4)) {
                case 0: vs->as.fmt = AUD_FMT_U8; break;
                case 1: vs->as.fmt = AUD_FMT_S8; break;
                case 2: vs->as.fmt = AUD_FMT_U16; break;
                case 3: vs->as.fmt = AUD_FMT_S16; break;
                case 4: vs->as.fmt = AUD_FMT_U32; break;
                case 5: vs->as.fmt = AUD_FMT_S32; break;
                default:
                    printf("Invalid audio format %d\n", read_u8(data, 4));
                    vnc_client_error(vs);
                    break;
                }
                vs->as.nchannels = read_u8(data, 5);
                if (vs->as.nchannels != 1 && vs->as.nchannels != 2) {
                    printf("Invalid audio channel coount %d\n",
                           read_u8(data, 5));
                    vnc_client_error(vs);
                    break;
                }
                vs->as.freq = read_u32(data, 6);
                break;
            default:
                printf ("Invalid audio message %d\n", read_u8(data, 4));
                vnc_client_error(vs);
                break;
            }
            break;

        default:
            printf("Msg: %d\n", read_u16(data, 0));
            vnc_client_error(vs);
            break;
        }
        break;
    default:
        printf("Msg: %d\n", data[0]);
        vnc_client_error(vs);
        break;
    }

    vnc_read_when(vs, protocol_client_msg, 1);
    return 0;
}
