static void coroutine_fn v9fs_link(void *opaque)
{
    V9fsPDU *pdu = opaque;
    int32_t dfid, oldfid;
    V9fsFidState *dfidp, *oldfidp;
    V9fsString name;
    size_t offset = 7;
    int err = 0;

    v9fs_string_init(&name);
    err = pdu_unmarshal(pdu, offset, "dds", &dfid, &oldfid, &name);
    if (err < 0) {
        goto out_nofid;
    }
    trace_v9fs_link(pdu->tag, pdu->id, dfid, oldfid, name.data);

    if (name_is_illegal(name.data)) {
        err = -ENOENT;
        goto out_nofid;
    }

    if (!strcmp(".", name.data) || !strcmp("..", name.data)) {
        err = -EEXIST;
        goto out_nofid;
    }

    dfidp = get_fid(pdu, dfid);
    if (dfidp == NULL) {
        err = -ENOENT;
        goto out_nofid;
    }

    oldfidp = get_fid(pdu, oldfid);
    if (oldfidp == NULL) {
        err = -ENOENT;
        goto out;
    }
    err = v9fs_co_link(pdu, oldfidp, dfidp, &name);
    if (!err) {
        err = offset;
    }
    put_fid(pdu, oldfidp);
out:
    put_fid(pdu, dfidp);
out_nofid:
    v9fs_string_free(&name);
    pdu_complete(pdu, err);
}
