static int ghash_final(struct shash_desc *desc, u8 *dst)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	struct ghash_ctx *ctx = crypto_shash_ctx(desc->tfm);
	u8 *buf = dctx->buffer;

	if (!ctx->gf128)
		return -ENOKEY;

	ghash_flush(ctx, dctx);
	memcpy(dst, buf, GHASH_BLOCK_SIZE);

	return 0;
}
