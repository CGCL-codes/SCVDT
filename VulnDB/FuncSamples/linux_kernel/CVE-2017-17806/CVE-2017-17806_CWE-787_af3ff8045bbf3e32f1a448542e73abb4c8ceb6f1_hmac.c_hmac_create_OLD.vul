static int hmac_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	struct shash_instance *inst;
	struct crypto_alg *alg;
	struct shash_alg *salg;
	int err;
	int ds;
	int ss;

	err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_SHASH);
	if (err)
		return err;

	salg = shash_attr_alg(tb[1], 0, 0);
	if (IS_ERR(salg))
		return PTR_ERR(salg);

	err = -EINVAL;
	ds = salg->digestsize;
	ss = salg->statesize;
	alg = &salg->base;
	if (ds > alg->cra_blocksize ||
	    ss < alg->cra_blocksize)
		goto out_put_alg;

	inst = shash_alloc_instance("hmac", alg);
	err = PTR_ERR(inst);
	if (IS_ERR(inst))
		goto out_put_alg;

	err = crypto_init_shash_spawn(shash_instance_ctx(inst), salg,
				      shash_crypto_instance(inst));
	if (err)
		goto out_free_inst;

	inst->alg.base.cra_priority = alg->cra_priority;
	inst->alg.base.cra_blocksize = alg->cra_blocksize;
	inst->alg.base.cra_alignmask = alg->cra_alignmask;

	ss = ALIGN(ss, alg->cra_alignmask + 1);
	inst->alg.digestsize = ds;
	inst->alg.statesize = ss;

	inst->alg.base.cra_ctxsize = sizeof(struct hmac_ctx) +
				     ALIGN(ss * 2, crypto_tfm_ctx_alignment());

	inst->alg.base.cra_init = hmac_init_tfm;
	inst->alg.base.cra_exit = hmac_exit_tfm;

	inst->alg.init = hmac_init;
	inst->alg.update = hmac_update;
	inst->alg.final = hmac_final;
	inst->alg.finup = hmac_finup;
	inst->alg.export = hmac_export;
	inst->alg.import = hmac_import;
	inst->alg.setkey = hmac_setkey;

	err = shash_register_instance(tmpl, inst);
	if (err) {
out_free_inst:
		shash_free_instance(shash_crypto_instance(inst));
	}

out_put_alg:
	crypto_mod_put(alg);
	return err;
}
