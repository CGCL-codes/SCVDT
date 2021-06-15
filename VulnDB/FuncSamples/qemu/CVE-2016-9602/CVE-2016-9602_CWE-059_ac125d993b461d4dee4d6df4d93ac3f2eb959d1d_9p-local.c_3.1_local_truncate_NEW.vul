static int local_truncate(FsContext *ctx, V9fsPath *fs_path, off_t size)
{
    int fd, ret;

    fd = local_open_nofollow(ctx, fs_path->data, O_WRONLY, 0);
    if (fd == -1) {
        return -1;
    }
    ret = ftruncate(fd, size);
    close_preserve_errno(fd);
    return ret;
}
