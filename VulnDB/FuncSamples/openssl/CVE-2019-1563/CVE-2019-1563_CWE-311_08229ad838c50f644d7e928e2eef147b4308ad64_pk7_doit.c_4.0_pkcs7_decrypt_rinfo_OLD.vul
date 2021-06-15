static int pkcs7_decrypt_rinfo(unsigned char **pek, int *peklen,
                               PKCS7_RECIP_INFO *ri, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *ek = NULL;
    size_t eklen;

    int ret = -1;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        return -1;

    if (EVP_PKEY_decrypt_init(pctx) <= 0)
        goto err;

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DECRYPT,
                          EVP_PKEY_CTRL_PKCS7_DECRYPT, 0, ri) <= 0) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, PKCS7_R_CTRL_ERROR);
        goto err;
    }

    if (EVP_PKEY_decrypt(pctx, NULL, &eklen,
                         ri->enc_key->data, ri->enc_key->length) <= 0)
        goto err;

    ek = OPENSSL_malloc(eklen);

    if (ek == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_decrypt(pctx, ek, &eklen,
                         ri->enc_key->data, ri->enc_key->length) <= 0) {
        ret = 0;
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, ERR_R_EVP_LIB);
        goto err;
    }

    ret = 1;

    OPENSSL_clear_free(*pek, *peklen);
    *pek = ek;
    *peklen = eklen;

 err:
    EVP_PKEY_CTX_free(pctx);
    if (!ret)
        OPENSSL_free(ek);

    return ret;
}
