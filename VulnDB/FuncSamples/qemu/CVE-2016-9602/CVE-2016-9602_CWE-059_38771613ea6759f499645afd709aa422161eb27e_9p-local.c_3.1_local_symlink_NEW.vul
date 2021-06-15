static int local_symlink(FsContext *fs_ctx, const char *oldpath,
                         V9fsPath *dir_path, const char *name, FsCred *credp)
{
    int err = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dir_path->data);
    if (dirfd == -1) {
        return -1;
    }

    /* Determine the security model */
    if (fs_ctx->export_flags & V9FS_SM_MAPPED ||
        fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        int fd;
        ssize_t oldpath_size, write_size;

        fd = openat_file(dirfd, name, O_CREAT | O_EXCL | O_RDWR,
                         SM_LOCAL_MODE_BITS);
        if (fd == -1) {
            goto out;
        }
        /* Write the oldpath (target) to the file. */
        oldpath_size = strlen(oldpath);
        do {
            write_size = write(fd, (void *)oldpath, oldpath_size);
        } while (write_size == -1 && errno == EINTR);
        close_preserve_errno(fd);

        if (write_size != oldpath_size) {
            goto err_end;
        }
        /* Set cleint credentials in symlink's xattr */
        credp->fc_mode = credp->fc_mode | S_IFLNK;

        if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
            err = local_set_xattrat(dirfd, name, credp);
        } else {
            err = local_set_mapped_file_attrat(dirfd, name, credp);
        }
        if (err == -1) {
            goto err_end;
        }
    } else if (fs_ctx->export_flags & V9FS_SM_PASSTHROUGH ||
               fs_ctx->export_flags & V9FS_SM_NONE) {
        err = symlinkat(oldpath, dirfd, name);
        if (err) {
            goto out;
        }
        err = fchownat(dirfd, name, credp->fc_uid, credp->fc_gid,
                       AT_SYMLINK_NOFOLLOW);
        if (err == -1) {
            /*
             * If we fail to change ownership and if we are
             * using security model none. Ignore the error
             */
            if ((fs_ctx->export_flags & V9FS_SEC_MASK) != V9FS_SM_NONE) {
                goto err_end;
            } else {
                err = 0;
            }
        }
    }
    goto out;

err_end:
    unlinkat_preserve_errno(dirfd, name, 0);
out:
    close_preserve_errno(dirfd);
    return err;
}
