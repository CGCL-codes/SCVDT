static int crypto_skcipher_init_tfm(struct crypto_tfm *tfm)
{
	struct crypto_skcipher *skcipher = __crypto_skcipher_cast(tfm);
	struct skcipher_alg *alg = crypto_skcipher_alg(skcipher);

	if (tfm->__crt_alg->cra_type == &crypto_blkcipher_type)
		return crypto_init_skcipher_ops_blkcipher(tfm);

	if (tfm->__crt_alg->cra_type == &crypto_ablkcipher_type ||
	    tfm->__crt_alg->cra_type == &crypto_givcipher_type)
		return crypto_init_skcipher_ops_ablkcipher(tfm);

	skcipher->setkey = alg->setkey;
	skcipher->encrypt = alg->encrypt;
	skcipher->decrypt = alg->decrypt;
	skcipher->ivsize = alg->ivsize;
	skcipher->keysize = alg->max_keysize;

	if (alg->exit)
		skcipher->base.exit = crypto_skcipher_exit_tfm;

	if (alg->init)
		return alg->init(skcipher);

	return 0;
}
