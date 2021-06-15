static int local_chown(FsContext *fs_ctx, V9fsPath *fs_path, FsCred *credp)
{
    char *dirpath = g_path_get_dirname(fs_path->data);
    char *name = g_path_get_basename(fs_path->data);
    int ret = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dirpath);
    if (dirfd == -1) {
        goto out;
    }

    if ((credp->fc_uid == -1 && credp->fc_gid == -1) ||
        (fs_ctx->export_flags & V9FS_SM_PASSTHROUGH) ||
        (fs_ctx->export_flags & V9FS_SM_NONE)) {
        ret = fchownat(dirfd, name, credp->fc_uid, credp->fc_gid,
                       AT_SYMLINK_NOFOLLOW);
    } else if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
        ret = local_set_xattrat(dirfd, name, credp);
    } else if (fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        ret = local_set_mapped_file_attrat(dirfd, name, credp);
    }

    close_preserve_errno(dirfd);
out:
    g_free(name);
    g_free(dirpath);
    return ret;
}
