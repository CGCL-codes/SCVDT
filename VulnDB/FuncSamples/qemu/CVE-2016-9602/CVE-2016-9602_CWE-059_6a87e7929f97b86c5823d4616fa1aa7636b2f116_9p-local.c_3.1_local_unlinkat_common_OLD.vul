static int local_unlinkat_common(FsContext *ctx, int dirfd, const char *name,
                                 int flags)
{
    int ret = -1;

    if (ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        int map_dirfd;

        if (flags == AT_REMOVEDIR) {
            int fd;

            fd = openat_dir(dirfd, name);
            if (fd == -1) {
                goto err_out;
            }
            /*
             * If directory remove .virtfs_metadata contained in the
             * directory
             */
            ret = unlinkat(fd, VIRTFS_META_DIR, AT_REMOVEDIR);
            close_preserve_errno(fd);
            if (ret < 0 && errno != ENOENT) {
                /*
                 * We didn't had the .virtfs_metadata file. May be file created
                 * in non-mapped mode ?. Ignore ENOENT.
                 */
                goto err_out;
            }
        }
        /*
         * Now remove the name from parent directory
         * .virtfs_metadata directory.
         */
        map_dirfd = openat_dir(dirfd, VIRTFS_META_DIR);
        ret = unlinkat(map_dirfd, name, 0);
        close_preserve_errno(map_dirfd);
        if (ret < 0 && errno != ENOENT) {
            /*
             * We didn't had the .virtfs_metadata file. May be file created
             * in non-mapped mode ?. Ignore ENOENT.
             */
            goto err_out;
        }
    }

    ret = unlinkat(dirfd, name, flags);
err_out:
    return ret;
}
