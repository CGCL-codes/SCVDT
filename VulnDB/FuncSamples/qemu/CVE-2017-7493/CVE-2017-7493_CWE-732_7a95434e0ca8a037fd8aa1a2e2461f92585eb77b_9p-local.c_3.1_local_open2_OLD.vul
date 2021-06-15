static int local_open2(FsContext *fs_ctx, V9fsPath *dir_path, const char *name,
                       int flags, FsCred *credp, V9fsFidOpenState *fs)
{
    int fd = -1;
    int err = -1;
    int dirfd;

    /*
     * Mark all the open to not follow symlinks
     */
    flags |= O_NOFOLLOW;

    dirfd = local_opendir_nofollow(fs_ctx, dir_path->data);
    if (dirfd == -1) {
        return -1;
    }

    /* Determine the security model */
    if (fs_ctx->export_flags & V9FS_SM_MAPPED ||
        fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        fd = openat_file(dirfd, name, flags, SM_LOCAL_MODE_BITS);
        if (fd == -1) {
            goto out;
        }
        credp->fc_mode = credp->fc_mode|S_IFREG;
        if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
            /* Set cleint credentials in xattr */
            err = local_set_xattrat(dirfd, name, credp);
        } else {
            err = local_set_mapped_file_attrat(dirfd, name, credp);
        }
        if (err == -1) {
            goto err_end;
        }
    } else if ((fs_ctx->export_flags & V9FS_SM_PASSTHROUGH) ||
               (fs_ctx->export_flags & V9FS_SM_NONE)) {
        fd = openat_file(dirfd, name, flags, credp->fc_mode);
        if (fd == -1) {
            goto out;
        }
        err = local_set_cred_passthrough(fs_ctx, dirfd, name, credp);
        if (err == -1) {
            goto err_end;
        }
    }
    err = fd;
    fs->fd = fd;
    goto out;

err_end:
    unlinkat_preserve_errno(dirfd, name,
                            flags & O_DIRECTORY ? AT_REMOVEDIR : 0);
    close_preserve_errno(fd);
out:
    close_preserve_errno(dirfd);
    return err;
}
