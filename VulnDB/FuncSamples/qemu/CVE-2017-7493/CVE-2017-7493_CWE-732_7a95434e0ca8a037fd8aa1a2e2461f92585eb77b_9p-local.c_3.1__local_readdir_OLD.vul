static struct dirent *local_readdir(FsContext *ctx, V9fsFidOpenState *fs)
{
    struct dirent *entry;

again:
    entry = readdir(fs->dir.stream);
    if (!entry) {
        return NULL;
    }

    if (ctx->export_flags & V9FS_SM_MAPPED) {
        entry->d_type = DT_UNKNOWN;
    } else if (ctx->export_flags & V9FS_SM_MAPPED_FILE) {
        if (!strcmp(entry->d_name, VIRTFS_META_DIR)) {
            /* skp the meta data directory */
            goto again;
        }
        entry->d_type = DT_UNKNOWN;
    }

    return entry;
}
