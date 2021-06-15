int qcow2_refcount_init(BlockDriverState *bs)
{
    BDRVQcowState *s = bs->opaque;
    unsigned int refcount_table_size2, i;
    int ret;

    assert(s->refcount_table_size <= INT_MAX / sizeof(uint64_t));
    refcount_table_size2 = s->refcount_table_size * sizeof(uint64_t);
    s->refcount_table = g_malloc(refcount_table_size2);
    if (s->refcount_table_size > 0) {
        BLKDBG_EVENT(bs->file, BLKDBG_REFTABLE_LOAD);
        ret = bdrv_pread(bs->file, s->refcount_table_offset,
                         s->refcount_table, refcount_table_size2);
        if (ret != refcount_table_size2)
            goto fail;
        for(i = 0; i < s->refcount_table_size; i++)
            be64_to_cpus(&s->refcount_table[i]);
    }
    return 0;
 fail:
    return -ENOMEM;
}
