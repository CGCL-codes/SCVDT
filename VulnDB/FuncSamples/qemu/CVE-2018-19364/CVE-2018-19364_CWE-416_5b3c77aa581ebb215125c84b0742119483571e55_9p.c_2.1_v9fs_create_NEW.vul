static void coroutine_fn v9fs_create(void *opaque)
{
    int32_t fid;
    int err = 0;
    size_t offset = 7;
    V9fsFidState *fidp;
    V9fsQID qid;
    int32_t perm;
    int8_t mode;
    V9fsPath path;
    struct stat stbuf;
    V9fsString name;
    V9fsString extension;
    int iounit;
    V9fsPDU *pdu = opaque;
    V9fsState *s = pdu->s;

    v9fs_path_init(&path);
    v9fs_string_init(&name);
    v9fs_string_init(&extension);
    err = pdu_unmarshal(pdu, offset, "dsdbs", &fid, &name,
                        &perm, &mode, &extension);
    if (err < 0) {
        goto out_nofid;
    }
    trace_v9fs_create(pdu->tag, pdu->id, fid, name.data, perm, mode);

    if (name_is_illegal(name.data)) {
        err = -ENOENT;
        goto out_nofid;
    }

    if (!strcmp(".", name.data) || !strcmp("..", name.data)) {
        err = -EEXIST;
        goto out_nofid;
    }

    fidp = get_fid(pdu, fid);
    if (fidp == NULL) {
        err = -EINVAL;
        goto out_nofid;
    }
    if (fidp->fid_type != P9_FID_NONE) {
        err = -EINVAL;
        goto out;
    }
    if (perm & P9_STAT_MODE_DIR) {
        err = v9fs_co_mkdir(pdu, fidp, &name, perm & 0777,
                            fidp->uid, -1, &stbuf);
        if (err < 0) {
            goto out;
        }
        err = v9fs_co_name_to_path(pdu, &fidp->path, name.data, &path);
        if (err < 0) {
            goto out;
        }
        v9fs_path_write_lock(s);
        v9fs_path_copy(&fidp->path, &path);
        v9fs_path_unlock(s);
        err = v9fs_co_opendir(pdu, fidp);
        if (err < 0) {
            goto out;
        }
        fidp->fid_type = P9_FID_DIR;
    } else if (perm & P9_STAT_MODE_SYMLINK) {
        err = v9fs_co_symlink(pdu, fidp, &name,
                              extension.data, -1 , &stbuf);
        if (err < 0) {
            goto out;
        }
        err = v9fs_co_name_to_path(pdu, &fidp->path, name.data, &path);
        if (err < 0) {
            goto out;
        }
        v9fs_path_write_lock(s);
        v9fs_path_copy(&fidp->path, &path);
        v9fs_path_unlock(s);
    } else if (perm & P9_STAT_MODE_LINK) {
        int32_t ofid = atoi(extension.data);
        V9fsFidState *ofidp = get_fid(pdu, ofid);
        if (ofidp == NULL) {
            err = -EINVAL;
            goto out;
        }
        err = v9fs_co_link(pdu, ofidp, fidp, &name);
        put_fid(pdu, ofidp);
        if (err < 0) {
            goto out;
        }
        err = v9fs_co_name_to_path(pdu, &fidp->path, name.data, &path);
        if (err < 0) {
            fidp->fid_type = P9_FID_NONE;
            goto out;
        }
        v9fs_path_write_lock(s);
        v9fs_path_copy(&fidp->path, &path);
        v9fs_path_unlock(s);
        err = v9fs_co_lstat(pdu, &fidp->path, &stbuf);
        if (err < 0) {
            fidp->fid_type = P9_FID_NONE;
            goto out;
        }
    } else if (perm & P9_STAT_MODE_DEVICE) {
        char ctype;
        uint32_t major, minor;
        mode_t nmode = 0;

        if (sscanf(extension.data, "%c %u %u", &ctype, &major, &minor) != 3) {
            err = -errno;
            goto out;
        }

        switch (ctype) {
        case 'c':
            nmode = S_IFCHR;
            break;
        case 'b':
            nmode = S_IFBLK;
            break;
        default:
            err = -EIO;
            goto out;
        }

        nmode |= perm & 0777;
        err = v9fs_co_mknod(pdu, fidp, &name, fidp->uid, -1,
                            makedev(major, minor), nmode, &stbuf);
        if (err < 0) {
            goto out;
        }
        err = v9fs_co_name_to_path(pdu, &fidp->path, name.data, &path);
        if (err < 0) {
            goto out;
        }
        v9fs_path_write_lock(s);
        v9fs_path_copy(&fidp->path, &path);
        v9fs_path_unlock(s);
    } else if (perm & P9_STAT_MODE_NAMED_PIPE) {
        err = v9fs_co_mknod(pdu, fidp, &name, fidp->uid, -1,
                            0, S_IFIFO | (perm & 0777), &stbuf);
        if (err < 0) {
            goto out;
        }
        err = v9fs_co_name_to_path(pdu, &fidp->path, name.data, &path);
        if (err < 0) {
            goto out;
        }
        v9fs_path_write_lock(s);
        v9fs_path_copy(&fidp->path, &path);
        v9fs_path_unlock(s);
    } else if (perm & P9_STAT_MODE_SOCKET) {
        err = v9fs_co_mknod(pdu, fidp, &name, fidp->uid, -1,
                            0, S_IFSOCK | (perm & 0777), &stbuf);
        if (err < 0) {
            goto out;
        }
        err = v9fs_co_name_to_path(pdu, &fidp->path, name.data, &path);
        if (err < 0) {
            goto out;
        }
        v9fs_path_write_lock(s);
        v9fs_path_copy(&fidp->path, &path);
        v9fs_path_unlock(s);
    } else {
        err = v9fs_co_open2(pdu, fidp, &name, -1,
                            omode_to_uflags(mode)|O_CREAT, perm, &stbuf);
        if (err < 0) {
            goto out;
        }
        fidp->fid_type = P9_FID_FILE;
        fidp->open_flags = omode_to_uflags(mode);
        if (fidp->open_flags & O_EXCL) {
            /*
             * We let the host file system do O_EXCL check
             * We should not reclaim such fd
             */
            fidp->flags |= FID_NON_RECLAIMABLE;
        }
    }
    iounit = get_iounit(pdu, &fidp->path);
    stat_to_qid(&stbuf, &qid);
    err = pdu_marshal(pdu, offset, "Qd", &qid, iounit);
    if (err < 0) {
        goto out;
    }
    err += offset;
    trace_v9fs_create_return(pdu->tag, pdu->id,
                             qid.type, qid.version, qid.path, iounit);
out:
    put_fid(pdu, fidp);
out_nofid:
   pdu_complete(pdu, err);
   v9fs_string_free(&name);
   v9fs_string_free(&extension);
   v9fs_path_free(&path);
}
