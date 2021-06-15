static SCSIRequest *scsi_new_request(SCSIDevice *d, uint32_t tag,
                                     uint32_t lun, void *hba_private)
{
    SCSIDiskState *s = DO_UPCAST(SCSIDiskState, qdev, d);
    SCSIRequest *req;
    SCSIDiskReq *r;

    req = scsi_req_alloc(&scsi_disk_reqops, &s->qdev, tag, lun, hba_private);
    r = DO_UPCAST(SCSIDiskReq, req, req);
    r->iov.iov_base = qemu_blockalign(s->bs, SCSI_DMA_BUF_SIZE);
    return req;
}
