static int
smbhash(unsigned char *out, const unsigned char *in, unsigned char *key)
{
	int rc;
	unsigned char key2[8];
	struct crypto_skcipher *tfm_des;
	struct scatterlist sgin, sgout;
	struct skcipher_request *req;

	str_to_key(key, key2);

	tfm_des = crypto_alloc_skcipher("ecb(des)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm_des)) {
		rc = PTR_ERR(tfm_des);
		cifs_dbg(VFS, "could not allocate des crypto API\n");
		goto smbhash_err;
	}

	req = skcipher_request_alloc(tfm_des, GFP_KERNEL);
	if (!req) {
		rc = -ENOMEM;
		cifs_dbg(VFS, "could not allocate des crypto API\n");
		goto smbhash_free_skcipher;
	}

	crypto_skcipher_setkey(tfm_des, key2, 8);

	sg_init_one(&sgin, in, 8);
	sg_init_one(&sgout, out, 8);

	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, &sgin, &sgout, 8, NULL);

	rc = crypto_skcipher_encrypt(req);
	if (rc)
		cifs_dbg(VFS, "could not encrypt crypt key rc: %d\n", rc);

	skcipher_request_free(req);

smbhash_free_skcipher:
	crypto_free_skcipher(tfm_des);
smbhash_err:
	return rc;
}
