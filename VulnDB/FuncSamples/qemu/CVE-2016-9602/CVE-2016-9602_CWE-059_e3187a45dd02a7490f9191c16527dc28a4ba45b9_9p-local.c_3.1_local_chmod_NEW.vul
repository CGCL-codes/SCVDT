static int local_chmod(FsContext *fs_ctx, V9fsPath *fs_path, FsCred *credp)
{
    char *dirpath = g_path_get_dirname(fs_path->data);
    char *name = g_path_get_basename(fs_path->data);
    int ret = -1;
    int dirfd;

    dirfd = local_opendir_nofollow(fs_ctx, dirpath);
    if (dirfd == -1) {
        goto out;
    }

    if (fs_ctx->export_flags & V9FS_SM_MAPPED) {
        ret = local_set_xattrat(dirfd, name, credp);
    } else if (fs_ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        ret = local_set_mapped_file_attrat(dirfd, name, credp);
    } else if (fs_ctx->export_flags & V9FS_SM_PASSTHROUGH ||
               fs_ctx->export_flags & V9FS_SM_NONE) {
        ret = fchmodat_nofollow(dirfd, name, credp->fc_mode);
    }
    close_preserve_errno(dirfd);

out:
    g_free(dirpath);
    g_free(name);
    return ret;
}
