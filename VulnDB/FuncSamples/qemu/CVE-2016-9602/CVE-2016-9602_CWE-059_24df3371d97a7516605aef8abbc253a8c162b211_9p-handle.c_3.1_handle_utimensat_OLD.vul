static int handle_utimensat(FsContext *ctx, V9fsPath *fs_path,
                            const struct timespec *buf)
{
    int ret;
#ifdef CONFIG_UTIMENSAT
    int fd;
    struct handle_data *data = (struct handle_data *)ctx->private;

    fd = open_by_handle(data->mountfd, fs_path->data, O_NONBLOCK);
    if (fd < 0) {
        return fd;
    }
    ret = futimens(fd, buf);
    close(fd);
#else
    ret = -1;
    errno = ENOSYS;
#endif
    return ret;
}
