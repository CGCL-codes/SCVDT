void vnc_zrle_clear(VncState *vs)
{
    if (vs->zrle.stream.opaque) {
        deflateEnd(&vs->zrle.stream);
    }
    buffer_free(&vs->zrle.zrle);
    buffer_free(&vs->zrle.fb);
    buffer_free(&vs->zrle.zlib);
}
