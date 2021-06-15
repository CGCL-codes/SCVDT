static int megasas_pd_get_info_submit(SCSIDevice *sdev, int lun,
                                      MegasasCmd *cmd)
{
    struct mfi_pd_info *info = cmd->iov_buf;
    size_t dcmd_size = sizeof(struct mfi_pd_info);
    uint64_t pd_size;
    uint16_t pd_id = ((sdev->id & 0xFF) << 8) | (lun & 0xFF);
    uint8_t cmdbuf[6];
    SCSIRequest *req;
    size_t len, resid;

    if (!cmd->iov_buf) {
        cmd->iov_buf = g_malloc0(dcmd_size);
        info = cmd->iov_buf;
        info->inquiry_data[0] = 0x7f; /* Force PQual 0x3, PType 0x1f */
        info->vpd_page83[0] = 0x7f;
        megasas_setup_inquiry(cmdbuf, 0, sizeof(info->inquiry_data));
        req = scsi_req_new(sdev, cmd->index, lun, cmdbuf, cmd);
        if (!req) {
            trace_megasas_dcmd_req_alloc_failed(cmd->index,
                                                "PD get info std inquiry");
            g_free(cmd->iov_buf);
            cmd->iov_buf = NULL;
            return MFI_STAT_FLASH_ALLOC_FAIL;
        }
        trace_megasas_dcmd_internal_submit(cmd->index,
                                           "PD get info std inquiry", lun);
        len = scsi_req_enqueue(req);
        if (len > 0) {
            cmd->iov_size = len;
            scsi_req_continue(req);
        }
        return MFI_STAT_INVALID_STATUS;
    } else if (info->inquiry_data[0] != 0x7f && info->vpd_page83[0] == 0x7f) {
        megasas_setup_inquiry(cmdbuf, 0x83, sizeof(info->vpd_page83));
        req = scsi_req_new(sdev, cmd->index, lun, cmdbuf, cmd);
        if (!req) {
            trace_megasas_dcmd_req_alloc_failed(cmd->index,
                                                "PD get info vpd inquiry");
            return MFI_STAT_FLASH_ALLOC_FAIL;
        }
        trace_megasas_dcmd_internal_submit(cmd->index,
                                           "PD get info vpd inquiry", lun);
        len = scsi_req_enqueue(req);
        if (len > 0) {
            cmd->iov_size = len;
            scsi_req_continue(req);
        }
        return MFI_STAT_INVALID_STATUS;
    }
    /* Finished, set FW state */
    if ((info->inquiry_data[0] >> 5) == 0) {
        if (megasas_is_jbod(cmd->state)) {
            info->fw_state = cpu_to_le16(MFI_PD_STATE_SYSTEM);
        } else {
            info->fw_state = cpu_to_le16(MFI_PD_STATE_ONLINE);
        }
    } else {
        info->fw_state = cpu_to_le16(MFI_PD_STATE_OFFLINE);
    }

    info->ref.v.device_id = cpu_to_le16(pd_id);
    info->state.ddf.pd_type = cpu_to_le16(MFI_PD_DDF_TYPE_IN_VD|
                                          MFI_PD_DDF_TYPE_INTF_SAS);
    blk_get_geometry(sdev->conf.blk, &pd_size);
    info->raw_size = cpu_to_le64(pd_size);
    info->non_coerced_size = cpu_to_le64(pd_size);
    info->coerced_size = cpu_to_le64(pd_size);
    info->encl_device_id = 0xFFFF;
    info->slot_number = (sdev->id & 0xFF);
    info->path_info.count = 1;
    info->path_info.sas_addr[0] =
        cpu_to_le64(megasas_get_sata_addr(pd_id));
    info->connected_port_bitmap = 0x1;
    info->device_speed = 1;
    info->link_speed = 1;
    resid = dma_buf_read(cmd->iov_buf, dcmd_size, &cmd->qsg);
    g_free(cmd->iov_buf);
    cmd->iov_size = dcmd_size - resid;
    cmd->iov_buf = NULL;
    return MFI_STAT_OK;
}
