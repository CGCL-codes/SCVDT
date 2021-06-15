static int zrle_compress_data(VncState *vs, int level)
{
    z_streamp zstream = &vs->zrle.stream;

    buffer_reset(&vs->zrle.zlib);

    if (zstream->opaque != vs) {
        int err;

        zstream->zalloc = vnc_zlib_zalloc;
        zstream->zfree = vnc_zlib_zfree;

        err = deflateInit2(zstream, level, Z_DEFLATED, MAX_WBITS,
                           MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);

        if (err != Z_OK) {
            fprintf(stderr, "VNC: error initializing zlib\n");
            return -1;
        }

        zstream->opaque = vs;
    }

    /* reserve memory in output buffer */
    buffer_reserve(&vs->zrle.zlib, vs->zrle.zrle.offset + 64);

    /* set pointers */
    zstream->next_in = vs->zrle.zrle.buffer;
    zstream->avail_in = vs->zrle.zrle.offset;
    zstream->next_out = vs->zrle.zlib.buffer + vs->zrle.zlib.offset;
    zstream->avail_out = vs->zrle.zlib.capacity - vs->zrle.zlib.offset;
    zstream->data_type = Z_BINARY;

    /* start encoding */
    if (deflate(zstream, Z_SYNC_FLUSH) != Z_OK) {
        fprintf(stderr, "VNC: error during zrle compression\n");
        return -1;
    }

    vs->zrle.zlib.offset = vs->zrle.zlib.capacity - zstream->avail_out;
    return vs->zrle.zlib.offset;
}
