static void v9fs_attach(void *opaque)
{
    V9fsPDU *pdu = opaque;
    V9fsState *s = pdu->s;
    int32_t fid, afid, n_uname;
    V9fsString uname, aname;
    V9fsFidState *fidp;
    size_t offset = 7;
    V9fsQID qid;
    ssize_t err;

    v9fs_string_init(&uname);
    v9fs_string_init(&aname);
    err = pdu_unmarshal(pdu, offset, "ddssd", &fid,
                        &afid, &uname, &aname, &n_uname);
    if (err < 0) {
        goto out_nofid;
    }
    trace_v9fs_attach(pdu->tag, pdu->id, fid, afid, uname.data, aname.data);

    fidp = alloc_fid(s, fid);
    if (fidp == NULL) {
        err = -EINVAL;
        goto out_nofid;
    }
    fidp->uid = n_uname;
    err = v9fs_co_name_to_path(pdu, NULL, "/", &fidp->path);
    if (err < 0) {
        err = -EINVAL;
        clunk_fid(s, fid);
        goto out;
    }
    err = fid_to_qid(pdu, fidp, &qid);
    if (err < 0) {
        err = -EINVAL;
        clunk_fid(s, fid);
        goto out;
    }
    err = pdu_marshal(pdu, offset, "Q", &qid);
    if (err < 0) {
        clunk_fid(s, fid);
        goto out;
    }
    err += offset;
    memcpy(&s->root_qid, &qid, sizeof(qid));
    trace_v9fs_attach_return(pdu->tag, pdu->id,
                             qid.type, qid.version, qid.path);
    /*
     * disable migration if we haven't done already.
     * attach could get called multiple times for the same export.
     */
    if (!s->migration_blocker) {
        s->root_fid = fid;
        error_setg(&s->migration_blocker,
                   "Migration is disabled when VirtFS export path '%s' is mounted in the guest using mount_tag '%s'",
                   s->ctx.fs_root ? s->ctx.fs_root : "NULL", s->tag);
        migrate_add_blocker(s->migration_blocker);
    }
out:
    put_fid(pdu, fidp);
out_nofid:
    pdu_complete(pdu, err);
    v9fs_string_free(&uname);
    v9fs_string_free(&aname);
}
