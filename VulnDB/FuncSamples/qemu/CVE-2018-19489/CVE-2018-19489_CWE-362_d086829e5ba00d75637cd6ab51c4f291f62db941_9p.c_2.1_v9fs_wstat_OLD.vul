static void coroutine_fn v9fs_wstat(void *opaque)
{
    int32_t fid;
    int err = 0;
    int16_t unused;
    V9fsStat v9stat;
    size_t offset = 7;
    struct stat stbuf;
    V9fsFidState *fidp;
    V9fsPDU *pdu = opaque;

    v9fs_stat_init(&v9stat);
    err = pdu_unmarshal(pdu, offset, "dwS", &fid, &unused, &v9stat);
    if (err < 0) {
        goto out_nofid;
    }
    trace_v9fs_wstat(pdu->tag, pdu->id, fid,
                     v9stat.mode, v9stat.atime, v9stat.mtime);

    fidp = get_fid(pdu, fid);
    if (fidp == NULL) {
        err = -EINVAL;
        goto out_nofid;
    }
    /* do we need to sync the file? */
    if (donttouch_stat(&v9stat)) {
        err = v9fs_co_fsync(pdu, fidp, 0);
        goto out;
    }
    if (v9stat.mode != -1) {
        uint32_t v9_mode;
        err = v9fs_co_lstat(pdu, &fidp->path, &stbuf);
        if (err < 0) {
            goto out;
        }
        v9_mode = stat_to_v9mode(&stbuf);
        if ((v9stat.mode & P9_STAT_MODE_TYPE_BITS) !=
            (v9_mode & P9_STAT_MODE_TYPE_BITS)) {
            /* Attempting to change the type */
            err = -EIO;
            goto out;
        }
        err = v9fs_co_chmod(pdu, &fidp->path,
                            v9mode_to_mode(v9stat.mode,
                                           &v9stat.extension));
        if (err < 0) {
            goto out;
        }
    }
    if (v9stat.mtime != -1 || v9stat.atime != -1) {
        struct timespec times[2];
        if (v9stat.atime != -1) {
            times[0].tv_sec = v9stat.atime;
            times[0].tv_nsec = 0;
        } else {
            times[0].tv_nsec = UTIME_OMIT;
        }
        if (v9stat.mtime != -1) {
            times[1].tv_sec = v9stat.mtime;
            times[1].tv_nsec = 0;
        } else {
            times[1].tv_nsec = UTIME_OMIT;
        }
        err = v9fs_co_utimensat(pdu, &fidp->path, times);
        if (err < 0) {
            goto out;
        }
    }
    if (v9stat.n_gid != -1 || v9stat.n_uid != -1) {
        err = v9fs_co_chown(pdu, &fidp->path, v9stat.n_uid, v9stat.n_gid);
        if (err < 0) {
            goto out;
        }
    }
    if (v9stat.name.size != 0) {
        err = v9fs_complete_rename(pdu, fidp, -1, &v9stat.name);
        if (err < 0) {
            goto out;
        }
    }
    if (v9stat.length != -1) {
        err = v9fs_co_truncate(pdu, &fidp->path, v9stat.length);
        if (err < 0) {
            goto out;
        }
    }
    err = offset;
out:
    put_fid(pdu, fidp);
out_nofid:
    v9fs_stat_free(&v9stat);
    pdu_complete(pdu, err);
}
