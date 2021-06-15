static void coroutine_fn v9fs_lcreate(void *opaque)
{
    int32_t dfid, flags, mode;
    gid_t gid;
    ssize_t err = 0;
    ssize_t offset = 7;
    V9fsString name;
    V9fsFidState *fidp;
    struct stat stbuf;
    V9fsQID qid;
    int32_t iounit;
    V9fsPDU *pdu = opaque;

    v9fs_string_init(&name);
    err = pdu_unmarshal(pdu, offset, "dsddd", &dfid,
                        &name, &flags, &mode, &gid);
    if (err < 0) {
        goto out_nofid;
    }
    trace_v9fs_lcreate(pdu->tag, pdu->id, dfid, flags, mode, gid);

    if (name_is_illegal(name.data)) {
        err = -ENOENT;
        goto out_nofid;
    }

    if (!strcmp(".", name.data) || !strcmp("..", name.data)) {
        err = -EEXIST;
        goto out_nofid;
    }

    fidp = get_fid(pdu, dfid);
    if (fidp == NULL) {
        err = -ENOENT;
        goto out_nofid;
    }

    flags = get_dotl_openflags(pdu->s, flags);
    err = v9fs_co_open2(pdu, fidp, &name, gid,
                        flags | O_CREAT, mode, &stbuf);
    if (err < 0) {
        goto out;
    }
    fidp->fid_type = P9_FID_FILE;
    fidp->open_flags = flags;
    if (flags & O_EXCL) {
        /*
         * We let the host file system do O_EXCL check
         * We should not reclaim such fd
         */
        fidp->flags |= FID_NON_RECLAIMABLE;
    }
    iounit =  get_iounit(pdu, &fidp->path);
    stat_to_qid(&stbuf, &qid);
    err = pdu_marshal(pdu, offset, "Qd", &qid, iounit);
    if (err < 0) {
        goto out;
    }
    err += offset;
    trace_v9fs_lcreate_return(pdu->tag, pdu->id,
                              qid.type, qid.version, qid.path, iounit);
out:
    put_fid(pdu, fidp);
out_nofid:
    pdu_complete(pdu, err);
    v9fs_string_free(&name);
}
