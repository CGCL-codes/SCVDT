static int local_open(FsContext *ctx, V9fsPath *fs_path,
                      int flags, V9fsFidOpenState *fs)
{
    int fd;

    fd = local_open_nofollow(ctx, fs_path->data, flags, 0);
    if (fd == -1) {
        return -1;
    }
    fs->fd = fd;
    return fs->fd;
}
