int scsi_req_parse_cdb(SCSIDevice *dev, SCSICommand *cmd, uint8_t *buf)
{
    int rc;

    cmd->lba = -1;
    cmd->len = scsi_cdb_length(buf);

    switch (dev->type) {
    case TYPE_TAPE:
        rc = scsi_req_stream_xfer(cmd, dev, buf);
        break;
    case TYPE_MEDIUM_CHANGER:
        rc = scsi_req_medium_changer_xfer(cmd, dev, buf);
        break;
    default:
        rc = scsi_req_xfer(cmd, dev, buf);
        break;
    }

    if (rc != 0)
        return rc;

    memcpy(cmd->buf, buf, cmd->len);
    scsi_cmd_xfer_mode(cmd);
    cmd->lba = scsi_cmd_lba(cmd);
    return 0;
}
