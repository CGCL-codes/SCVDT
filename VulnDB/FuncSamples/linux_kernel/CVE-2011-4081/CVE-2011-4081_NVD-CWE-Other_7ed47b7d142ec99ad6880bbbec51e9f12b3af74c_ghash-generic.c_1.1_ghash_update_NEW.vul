static int ghash_update(struct shash_desc *desc,
			 const u8 *src, unsigned int srclen)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	struct ghash_ctx *ctx = crypto_shash_ctx(desc->tfm);
	u8 *dst = dctx->buffer;

	if (!ctx->gf128)
		return -ENOKEY;

	if (dctx->bytes) {
		int n = min(srclen, dctx->bytes);
		u8 *pos = dst + (GHASH_BLOCK_SIZE - dctx->bytes);

		dctx->bytes -= n;
		srclen -= n;

		while (n--)
			*pos++ ^= *src++;

		if (!dctx->bytes)
			gf128mul_4k_lle((be128 *)dst, ctx->gf128);
	}

	while (srclen >= GHASH_BLOCK_SIZE) {
		crypto_xor(dst, src, GHASH_BLOCK_SIZE);
		gf128mul_4k_lle((be128 *)dst, ctx->gf128);
		src += GHASH_BLOCK_SIZE;
		srclen -= GHASH_BLOCK_SIZE;
	}

	if (srclen) {
		dctx->bytes = GHASH_BLOCK_SIZE - srclen;
		while (srclen--)
			*dst++ ^= *src++;
	}

	return 0;
}
