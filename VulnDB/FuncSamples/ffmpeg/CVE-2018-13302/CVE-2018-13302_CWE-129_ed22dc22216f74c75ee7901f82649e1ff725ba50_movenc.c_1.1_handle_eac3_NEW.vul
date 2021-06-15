static int handle_eac3(MOVMuxContext *mov, AVPacket *pkt, MOVTrack *track)
{
    AC3HeaderInfo *hdr = NULL;
    struct eac3_info *info;
    int num_blocks, ret;

    if (!track->eac3_priv && !(track->eac3_priv = av_mallocz(sizeof(*info))))
        return AVERROR(ENOMEM);
    info = track->eac3_priv;

    if (avpriv_ac3_parse_header(&hdr, pkt->data, pkt->size) < 0) {
        /* drop the packets until we see a good one */
        if (!track->entry) {
            av_log(mov, AV_LOG_WARNING, "Dropping invalid packet from start of the stream\n");
            ret = 0;
        } else
            ret = AVERROR_INVALIDDATA;
        goto end;
    }

    info->data_rate = FFMAX(info->data_rate, hdr->bit_rate / 1000);
    num_blocks = hdr->num_blocks;

    if (!info->ec3_done) {
        /* AC-3 substream must be the first one */
        if (hdr->bitstream_id <= 10 && hdr->substreamid != 0) {
            ret = AVERROR(EINVAL);
            goto end;
        }

        /* this should always be the case, given that our AC-3 parser
         * concatenates dependent frames to their independent parent */
        if (hdr->frame_type == EAC3_FRAME_TYPE_INDEPENDENT) {
            /* substream ids must be incremental */
            if (hdr->substreamid > info->num_ind_sub + 1) {
                ret = AVERROR(EINVAL);
                goto end;
            }

            if (hdr->substreamid == info->num_ind_sub + 1) {
                //info->num_ind_sub++;
                avpriv_request_sample(track->par, "Multiple independent substreams");
                ret = AVERROR_PATCHWELCOME;
                goto end;
            } else if (hdr->substreamid < info->num_ind_sub ||
                       hdr->substreamid == 0 && info->substream[0].bsid) {
                info->ec3_done = 1;
                goto concatenate;
            }
        } else {
            if (hdr->substreamid != 0) {
                avpriv_request_sample(mov->fc, "Multiple non EAC3 independent substreams");
                ret = AVERROR_PATCHWELCOME;
                goto end;
            }
        }

        /* fill the info needed for the "dec3" atom */
        info->substream[hdr->substreamid].fscod = hdr->sr_code;
        info->substream[hdr->substreamid].bsid  = hdr->bitstream_id;
        info->substream[hdr->substreamid].bsmod = hdr->bitstream_mode;
        info->substream[hdr->substreamid].acmod = hdr->channel_mode;
        info->substream[hdr->substreamid].lfeon = hdr->lfe_on;

        /* Parse dependent substream(s), if any */
        if (pkt->size != hdr->frame_size) {
            int cumul_size = hdr->frame_size;
            int parent = hdr->substreamid;

            while (cumul_size != pkt->size) {
                GetBitContext gbc;
                int i;
                ret = avpriv_ac3_parse_header(&hdr, pkt->data + cumul_size, pkt->size - cumul_size);
                if (ret < 0)
                    goto end;
                if (hdr->frame_type != EAC3_FRAME_TYPE_DEPENDENT) {
                    ret = AVERROR(EINVAL);
                    goto end;
                }
                info->substream[parent].num_dep_sub++;
                ret /= 8;

                /* header is parsed up to lfeon, but custom channel map may be needed */
                init_get_bits8(&gbc, pkt->data + cumul_size + ret, pkt->size - cumul_size - ret);
                /* skip bsid */
                skip_bits(&gbc, 5);
                /* skip volume control params */
                for (i = 0; i < (hdr->channel_mode ? 1 : 2); i++) {
                    skip_bits(&gbc, 5); // skip dialog normalization
                    if (get_bits1(&gbc)) {
                        skip_bits(&gbc, 8); // skip compression gain word
                    }
                }
                /* get the dependent stream channel map, if exists */
                if (get_bits1(&gbc))
                    info->substream[parent].chan_loc |= (get_bits(&gbc, 16) >> 5) & 0x1f;
                else
                    info->substream[parent].chan_loc |= hdr->channel_mode;
                cumul_size += hdr->frame_size;
            }
        }
    }

concatenate:
    if (!info->num_blocks && num_blocks == 6) {
        ret = pkt->size;
        goto end;
    }
    else if (info->num_blocks + num_blocks > 6) {
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    if (!info->num_blocks) {
        ret = av_packet_ref(&info->pkt, pkt);
        if (!ret)
            info->num_blocks = num_blocks;
        goto end;
    } else {
        if ((ret = av_grow_packet(&info->pkt, pkt->size)) < 0)
            goto end;
        memcpy(info->pkt.data + info->pkt.size - pkt->size, pkt->data, pkt->size);
        info->num_blocks += num_blocks;
        info->pkt.duration += pkt->duration;
        if ((ret = av_copy_packet_side_data(&info->pkt, pkt)) < 0)
            goto end;
        if (info->num_blocks != 6)
            goto end;
        av_packet_unref(pkt);
        av_packet_move_ref(pkt, &info->pkt);
        info->num_blocks = 0;
    }
    ret = pkt->size;

end:
    av_free(hdr);

    return ret;
}
