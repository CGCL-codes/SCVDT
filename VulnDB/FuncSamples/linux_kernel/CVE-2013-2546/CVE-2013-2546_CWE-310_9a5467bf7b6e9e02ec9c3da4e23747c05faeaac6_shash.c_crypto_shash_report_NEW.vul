static int crypto_shash_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_hash rhash;
	struct shash_alg *salg = __crypto_shash_alg(alg);

	strncpy(rhash.type, "shash", sizeof(rhash.type));

	rhash.blocksize = alg->cra_blocksize;
	rhash.digestsize = salg->digestsize;

	if (nla_put(skb, CRYPTOCFGA_REPORT_HASH,
		    sizeof(struct crypto_report_hash), &rhash))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
