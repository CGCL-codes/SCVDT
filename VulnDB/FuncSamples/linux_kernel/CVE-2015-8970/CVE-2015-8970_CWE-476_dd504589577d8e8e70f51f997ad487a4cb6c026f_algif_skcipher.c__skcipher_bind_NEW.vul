static void *skcipher_bind(const char *name, u32 type, u32 mask)
{
	struct skcipher_tfm *tfm;
	struct crypto_skcipher *skcipher;

	tfm = kzalloc(sizeof(*tfm), GFP_KERNEL);
	if (!tfm)
		return ERR_PTR(-ENOMEM);

	skcipher = crypto_alloc_skcipher(name, type, mask);
	if (IS_ERR(skcipher)) {
		kfree(tfm);
		return ERR_CAST(skcipher);
	}

	tfm->skcipher = skcipher;

	return tfm;
}
