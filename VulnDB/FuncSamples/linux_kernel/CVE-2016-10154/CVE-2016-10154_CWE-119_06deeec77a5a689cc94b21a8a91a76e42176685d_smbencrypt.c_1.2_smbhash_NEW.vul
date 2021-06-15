static int
smbhash(unsigned char *out, const unsigned char *in, unsigned char *key)
{
	unsigned char key2[8];
	struct crypto_cipher *tfm_des;

	str_to_key(key, key2);

	tfm_des = crypto_alloc_cipher("des", 0, 0);
	if (IS_ERR(tfm_des)) {
		cifs_dbg(VFS, "could not allocate des crypto API\n");
		return PTR_ERR(tfm_des);
	}

	crypto_cipher_setkey(tfm_des, key2, 8);
	crypto_cipher_encrypt_one(tfm_des, out, in);
	crypto_free_cipher(tfm_des);

	return 0;
}
