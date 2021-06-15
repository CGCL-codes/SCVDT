static void coroutine_fn v9fs_walk(void *opaque)
{
    int name_idx;
    V9fsQID *qids = NULL;
    int i, err = 0;
    V9fsPath dpath, path;
    uint16_t nwnames;
    struct stat stbuf;
    size_t offset = 7;
    int32_t fid, newfid;
    V9fsString *wnames = NULL;
    V9fsFidState *fidp;
    V9fsFidState *newfidp = NULL;
    V9fsPDU *pdu = opaque;
    V9fsState *s = pdu->s;
    V9fsQID qid;

    err = pdu_unmarshal(pdu, offset, "ddw", &fid, &newfid, &nwnames);
    if (err < 0) {
        pdu_complete(pdu, err);
        return ;
    }
    offset += err;

    trace_v9fs_walk(pdu->tag, pdu->id, fid, newfid, nwnames);

    if (nwnames && nwnames <= P9_MAXWELEM) {
        wnames = g_malloc0(sizeof(wnames[0]) * nwnames);
        qids   = g_malloc0(sizeof(qids[0]) * nwnames);
        for (i = 0; i < nwnames; i++) {
            err = pdu_unmarshal(pdu, offset, "s", &wnames[i]);
            if (err < 0) {
                goto out_nofid;
            }
            if (name_is_illegal(wnames[i].data)) {
                err = -ENOENT;
                goto out_nofid;
            }
            offset += err;
        }
    } else if (nwnames > P9_MAXWELEM) {
        err = -EINVAL;
        goto out_nofid;
    }
    fidp = get_fid(pdu, fid);
    if (fidp == NULL) {
        err = -ENOENT;
        goto out_nofid;
    }

    v9fs_path_init(&dpath);
    v9fs_path_init(&path);

    err = fid_to_qid(pdu, fidp, &qid);
    if (err < 0) {
        goto out;
    }

    /*
     * Both dpath and path initially poin to fidp.
     * Needed to handle request with nwnames == 0
     */
    v9fs_path_copy(&dpath, &fidp->path);
    v9fs_path_copy(&path, &fidp->path);
    for (name_idx = 0; name_idx < nwnames; name_idx++) {
        if (not_same_qid(&pdu->s->root_qid, &qid) ||
            strcmp("..", wnames[name_idx].data)) {
            err = v9fs_co_name_to_path(pdu, &dpath, wnames[name_idx].data,
                                       &path);
            if (err < 0) {
                goto out;
            }

            err = v9fs_co_lstat(pdu, &path, &stbuf);
            if (err < 0) {
                goto out;
            }
            stat_to_qid(&stbuf, &qid);
            v9fs_path_copy(&dpath, &path);
        }
        memcpy(&qids[name_idx], &qid, sizeof(qid));
    }
    if (fid == newfid) {
        if (fidp->fid_type != P9_FID_NONE) {
            err = -EINVAL;
            goto out;
        }
        v9fs_path_write_lock(s);
        v9fs_path_copy(&fidp->path, &path);
        v9fs_path_unlock(s);
    } else {
        newfidp = alloc_fid(s, newfid);
        if (newfidp == NULL) {
            err = -EINVAL;
            goto out;
        }
        newfidp->uid = fidp->uid;
        v9fs_path_copy(&newfidp->path, &path);
    }
    err = v9fs_walk_marshal(pdu, nwnames, qids);
    trace_v9fs_walk_return(pdu->tag, pdu->id, nwnames, qids);
out:
    put_fid(pdu, fidp);
    if (newfidp) {
        put_fid(pdu, newfidp);
    }
    v9fs_path_free(&dpath);
    v9fs_path_free(&path);
out_nofid:
    pdu_complete(pdu, err);
    if (nwnames && nwnames <= P9_MAXWELEM) {
        for (name_idx = 0; name_idx < nwnames; name_idx++) {
            v9fs_string_free(&wnames[name_idx]);
        }
        g_free(wnames);
        g_free(qids);
    }
}
