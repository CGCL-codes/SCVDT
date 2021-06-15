static int __init big_key_init(void)
{
	struct crypto_skcipher *cipher;
	struct crypto_rng *rng;
	int ret;

	rng = crypto_alloc_rng(big_key_rng_name, 0, 0);
	if (IS_ERR(rng)) {
		pr_err("Can't alloc rng: %ld\n", PTR_ERR(rng));
		return PTR_ERR(rng);
	}

	big_key_rng = rng;

	/* seed RNG */
	ret = crypto_rng_reset(rng, NULL, crypto_rng_seedsize(rng));
	if (ret) {
		pr_err("Can't reset rng: %d\n", ret);
		goto error_rng;
	}

	/* init block cipher */
	cipher = crypto_alloc_skcipher(big_key_alg_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(cipher)) {
		ret = PTR_ERR(cipher);
		pr_err("Can't alloc crypto: %d\n", ret);
		goto error_rng;
	}

	big_key_skcipher = cipher;

	ret = register_key_type(&key_type_big_key);
	if (ret < 0) {
		pr_err("Can't register type: %d\n", ret);
		goto error_cipher;
	}

	return 0;

error_cipher:
	crypto_free_skcipher(big_key_skcipher);
error_rng:
	crypto_free_rng(big_key_rng);
	return ret;
}
