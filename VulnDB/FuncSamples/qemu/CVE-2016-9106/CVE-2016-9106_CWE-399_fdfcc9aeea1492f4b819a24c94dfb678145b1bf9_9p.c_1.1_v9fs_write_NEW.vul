static void coroutine_fn v9fs_write(void *opaque)
{
    ssize_t err;
    int32_t fid;
    uint64_t off;
    uint32_t count;
    int32_t len = 0;
    int32_t total = 0;
    size_t offset = 7;
    V9fsFidState *fidp;
    V9fsPDU *pdu = opaque;
    V9fsState *s = pdu->s;
    QEMUIOVector qiov_full;
    QEMUIOVector qiov;

    err = pdu_unmarshal(pdu, offset, "dqd", &fid, &off, &count);
    if (err < 0) {
        pdu_complete(pdu, err);
        return;
    }
    offset += err;
    v9fs_init_qiov_from_pdu(&qiov_full, pdu, offset, count, true);
    trace_v9fs_write(pdu->tag, pdu->id, fid, off, count, qiov_full.niov);

    fidp = get_fid(pdu, fid);
    if (fidp == NULL) {
        err = -EINVAL;
        goto out_nofid;
    }
    if (fidp->fid_type == P9_FID_FILE) {
        if (fidp->fs.fd == -1) {
            err = -EINVAL;
            goto out;
        }
    } else if (fidp->fid_type == P9_FID_XATTR) {
        /*
         * setxattr operation
         */
        err = v9fs_xattr_write(s, pdu, fidp, off, count,
                               qiov_full.iov, qiov_full.niov);
        goto out;
    } else {
        err = -EINVAL;
        goto out;
    }
    qemu_iovec_init(&qiov, qiov_full.niov);
    do {
        qemu_iovec_reset(&qiov);
        qemu_iovec_concat(&qiov, &qiov_full, total, qiov_full.size - total);
        if (0) {
            print_sg(qiov.iov, qiov.niov);
        }
        /* Loop in case of EINTR */
        do {
            len = v9fs_co_pwritev(pdu, fidp, qiov.iov, qiov.niov, off);
            if (len >= 0) {
                off   += len;
                total += len;
            }
        } while (len == -EINTR && !pdu->cancelled);
        if (len < 0) {
            /* IO error return the error */
            err = len;
            goto out_qiov;
        }
    } while (total < count && len > 0);

    offset = 7;
    err = pdu_marshal(pdu, offset, "d", total);
    if (err < 0) {
        goto out_qiov;
    }
    err += offset;
    trace_v9fs_write_return(pdu->tag, pdu->id, total, err);
out_qiov:
    qemu_iovec_destroy(&qiov);
out:
    put_fid(pdu, fidp);
out_nofid:
    qemu_iovec_destroy(&qiov_full);
    pdu_complete(pdu, err);
}
