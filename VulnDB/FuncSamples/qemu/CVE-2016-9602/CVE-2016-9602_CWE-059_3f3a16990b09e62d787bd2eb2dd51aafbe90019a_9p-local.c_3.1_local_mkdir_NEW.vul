static int local_mkdir(FsContext *fs_ctx, V9fsPath *dir_path,
                       const char *name, FsCred *credp)
{
    int err = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dir_path->data);
    if (dirfd == -1) {
        return -1;
    }

    if (fs_ctx->export_flags & V9FS_SM_MAPPED ||
        fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        err = mkdirat(dirfd, name, SM_LOCAL_DIR_MODE_BITS);
        if (err == -1) {
            goto out;
        }
        credp->fc_mode = credp->fc_mode | S_IFDIR;

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
        err = mkdirat(dirfd, name, credp->fc_mode);
        if (err == -1) {
            goto out;
        }
        err = local_set_cred_passthrough(fs_ctx, dirfd, name, credp);
        if (err == -1) {
            goto err_end;
        }
    }
    goto out;

err_end:
    unlinkat_preserve_errno(dirfd, name, AT_REMOVEDIR);
out:
    close_preserve_errno(dirfd);
    return err;
}
