static int megasas_dcmd_cfg_read(MegasasState *s, MegasasCmd *cmd)
{
    uint8_t data[4096] = { 0 };
    struct mfi_config_data *info;
    int num_pd_disks = 0, array_offset, ld_offset;
    BusChild *kid;

    if (cmd->iov_size > 4096) {
        return MFI_STAT_INVALID_PARAMETER;
    }

    QTAILQ_FOREACH(kid, &s->bus.qbus.children, sibling) {
        num_pd_disks++;
    }
    info = (struct mfi_config_data *)&data;
    /*
     * Array mapping:
     * - One array per SCSI device
     * - One logical drive per SCSI device
     *   spanning the entire device
     */
    info->array_count = num_pd_disks;
    info->array_size = sizeof(struct mfi_array) * num_pd_disks;
    info->log_drv_count = num_pd_disks;
    info->log_drv_size = sizeof(struct mfi_ld_config) * num_pd_disks;
    info->spares_count = 0;
    info->spares_size = sizeof(struct mfi_spare);
    info->size = sizeof(struct mfi_config_data) + info->array_size +
        info->log_drv_size;
    if (info->size > 4096) {
        return MFI_STAT_INVALID_PARAMETER;
    }

    array_offset = sizeof(struct mfi_config_data);
    ld_offset = array_offset + sizeof(struct mfi_array) * num_pd_disks;

    QTAILQ_FOREACH(kid, &s->bus.qbus.children, sibling) {
        SCSIDevice *sdev = SCSI_DEVICE(kid->child);
        uint16_t sdev_id = ((sdev->id & 0xFF) << 8) | (sdev->lun & 0xFF);
        struct mfi_array *array;
        struct mfi_ld_config *ld;
        uint64_t pd_size;
        int i;

        array = (struct mfi_array *)(data + array_offset);
        blk_get_geometry(sdev->conf.blk, &pd_size);
        array->size = cpu_to_le64(pd_size);
        array->num_drives = 1;
        array->array_ref = cpu_to_le16(sdev_id);
        array->pd[0].ref.v.device_id = cpu_to_le16(sdev_id);
        array->pd[0].ref.v.seq_num = 0;
        array->pd[0].fw_state = MFI_PD_STATE_ONLINE;
        array->pd[0].encl.pd = 0xFF;
        array->pd[0].encl.slot = (sdev->id & 0xFF);
        for (i = 1; i < MFI_MAX_ROW_SIZE; i++) {
            array->pd[i].ref.v.device_id = 0xFFFF;
            array->pd[i].ref.v.seq_num = 0;
            array->pd[i].fw_state = MFI_PD_STATE_UNCONFIGURED_GOOD;
            array->pd[i].encl.pd = 0xFF;
            array->pd[i].encl.slot = 0xFF;
        }
        array_offset += sizeof(struct mfi_array);
        ld = (struct mfi_ld_config *)(data + ld_offset);
        memset(ld, 0, sizeof(struct mfi_ld_config));
        ld->properties.ld.v.target_id = sdev->id;
        ld->properties.default_cache_policy = MR_LD_CACHE_READ_AHEAD |
            MR_LD_CACHE_READ_ADAPTIVE;
        ld->properties.current_cache_policy = MR_LD_CACHE_READ_AHEAD |
            MR_LD_CACHE_READ_ADAPTIVE;
        ld->params.state = MFI_LD_STATE_OPTIMAL;
        ld->params.stripe_size = 3;
        ld->params.num_drives = 1;
        ld->params.span_depth = 1;
        ld->params.is_consistent = 1;
        ld->span[0].start_block = 0;
        ld->span[0].num_blocks = cpu_to_le64(pd_size);
        ld->span[0].array_ref = cpu_to_le16(sdev_id);
        ld_offset += sizeof(struct mfi_ld_config);
    }

    cmd->iov_size -= dma_buf_read((uint8_t *)data, info->size, &cmd->qsg);
    return MFI_STAT_OK;
}
