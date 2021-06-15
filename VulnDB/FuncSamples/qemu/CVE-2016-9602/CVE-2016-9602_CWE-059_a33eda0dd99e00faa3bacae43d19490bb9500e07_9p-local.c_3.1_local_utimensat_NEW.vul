static int local_utimensat(FsContext *s, V9fsPath *fs_path,
                           const struct timespec *buf)
{
    char *dirpath = g_path_get_dirname(fs_path->data);
    char *name = g_path_get_basename(fs_path->data);
    int dirfd, ret = -1;

    dirfd = local_opendir_nofollow(s, dirpath);
    if (dirfd == -1) {
        goto out;
    }

    ret = utimensat(dirfd, name, buf, AT_SYMLINK_NOFOLLOW);
    close_preserve_errno(dirfd);
out:
    g_free(dirpath);
    g_free(name);
    return ret;
}
