static int megasas_ld_get_info_submit(SCSIDevice *sdev, int lun,
                                      MegasasCmd *cmd)
{
    struct mfi_ld_info *info = cmd->iov_buf;
    size_t dcmd_size = sizeof(struct mfi_ld_info);
    uint8_t cdb[6];
    SCSIRequest *req;
    ssize_t len, resid;
    uint16_t sdev_id = ((sdev->id & 0xFF) << 8) | (lun & 0xFF);
    uint64_t ld_size;

    if (!cmd->iov_buf) {
        cmd->iov_buf = g_malloc0(dcmd_size);
        info = cmd->iov_buf;
        megasas_setup_inquiry(cdb, 0x83, sizeof(info->vpd_page83));
        req = scsi_req_new(sdev, cmd->index, lun, cdb, cmd);
        if (!req) {
            trace_megasas_dcmd_req_alloc_failed(cmd->index,
                                                "LD get info vpd inquiry");
            g_free(cmd->iov_buf);
            cmd->iov_buf = NULL;
            return MFI_STAT_FLASH_ALLOC_FAIL;
        }
        trace_megasas_dcmd_internal_submit(cmd->index,
                                           "LD get info vpd inquiry", lun);
        len = scsi_req_enqueue(req);
        if (len > 0) {
            cmd->iov_size = len;
            scsi_req_continue(req);
        }
        return MFI_STAT_INVALID_STATUS;
    }

    info->ld_config.params.state = MFI_LD_STATE_OPTIMAL;
    info->ld_config.properties.ld.v.target_id = lun;
    info->ld_config.params.stripe_size = 3;
    info->ld_config.params.num_drives = 1;
    info->ld_config.params.is_consistent = 1;
    /* Logical device size is in blocks */
    blk_get_geometry(sdev->conf.blk, &ld_size);
    info->size = cpu_to_le64(ld_size);
    memset(info->ld_config.span, 0, sizeof(info->ld_config.span));
    info->ld_config.span[0].start_block = 0;
    info->ld_config.span[0].num_blocks = info->size;
    info->ld_config.span[0].array_ref = cpu_to_le16(sdev_id);

    resid = dma_buf_read(cmd->iov_buf, dcmd_size, &cmd->qsg);
    g_free(cmd->iov_buf);
    cmd->iov_size = dcmd_size - resid;
    cmd->iov_buf = NULL;
    return MFI_STAT_OK;
}
