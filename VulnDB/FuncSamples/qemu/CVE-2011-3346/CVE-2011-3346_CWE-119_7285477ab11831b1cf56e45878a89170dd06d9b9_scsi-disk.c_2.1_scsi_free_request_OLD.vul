static void scsi_free_request(SCSIRequest *req)
{
    SCSIDiskReq *r = DO_UPCAST(SCSIDiskReq, req, req);

    qemu_vfree(r->iov.iov_base);
}
