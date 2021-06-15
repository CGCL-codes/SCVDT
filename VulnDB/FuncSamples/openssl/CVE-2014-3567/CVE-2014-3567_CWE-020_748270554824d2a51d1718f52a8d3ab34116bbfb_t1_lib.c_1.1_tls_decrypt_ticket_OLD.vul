static int tls_decrypt_ticket(SSL *s, const unsigned char *etick, int eticklen,
				const unsigned char *sess_id, int sesslen,
				SSL_SESSION **psess)
	{
	SSL_SESSION *sess;
	unsigned char *sdec;
	const unsigned char *p;
	int slen, mlen, renew_ticket = 0;
	unsigned char tick_hmac[EVP_MAX_MD_SIZE];
	HMAC_CTX hctx;
	EVP_CIPHER_CTX ctx;
	SSL_CTX *tctx = s->initial_ctx;
	/* Need at least keyname + iv + some encrypted data */
	if (eticklen < 48)
		return 2;
	/* Initialize session ticket encryption and HMAC contexts */
	HMAC_CTX_init(&hctx);
	EVP_CIPHER_CTX_init(&ctx);
	if (tctx->tlsext_ticket_key_cb)
		{
		unsigned char *nctick = (unsigned char *)etick;
		int rv = tctx->tlsext_ticket_key_cb(s, nctick, nctick + 16,
							&ctx, &hctx, 0);
		if (rv < 0)
			return -1;
		if (rv == 0)
			return 2;
		if (rv == 2)
			renew_ticket = 1;
		}
	else
		{
		/* Check key name matches */
		if (memcmp(etick, tctx->tlsext_tick_key_name, 16))
			return 2;
		HMAC_Init_ex(&hctx, tctx->tlsext_tick_hmac_key, 16,
					tlsext_tick_md(), NULL);
		EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL,
				tctx->tlsext_tick_aes_key, etick + 16);
		}
	/* Attempt to process session ticket, first conduct sanity and
	 * integrity checks on ticket.
	 */
	mlen = HMAC_size(&hctx);
	if (mlen < 0)
		{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
		}
	eticklen -= mlen;
	/* Check HMAC of encrypted ticket */
	HMAC_Update(&hctx, etick, eticklen);
	HMAC_Final(&hctx, tick_hmac, NULL);
	HMAC_CTX_cleanup(&hctx);
	if (CRYPTO_memcmp(tick_hmac, etick + eticklen, mlen))
		return 2;
	/* Attempt to decrypt session data */
	/* Move p after IV to start of encrypted ticket, update length */
	p = etick + 16 + EVP_CIPHER_CTX_iv_length(&ctx);
	eticklen -= 16 + EVP_CIPHER_CTX_iv_length(&ctx);
	sdec = OPENSSL_malloc(eticklen);
	if (!sdec)
		{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
		}
	EVP_DecryptUpdate(&ctx, sdec, &slen, p, eticklen);
	if (EVP_DecryptFinal(&ctx, sdec + slen, &mlen) <= 0)
		{
		EVP_CIPHER_CTX_cleanup(&ctx);
		OPENSSL_free(sdec);
		return 2;
		}
	slen += mlen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	p = sdec;

	sess = d2i_SSL_SESSION(NULL, &p, slen);
	OPENSSL_free(sdec);
	if (sess)
		{
		/* The session ID, if non-empty, is used by some clients to
		 * detect that the ticket has been accepted. So we copy it to
		 * the session structure. If it is empty set length to zero
		 * as required by standard.
		 */
		if (sesslen)
			memcpy(sess->session_id, sess_id, sesslen);
		sess->session_id_length = sesslen;
		*psess = sess;
		if (renew_ticket)
			return 4;
		else
			return 3;
		}
        ERR_clear_error();
	/* For session parse failure, indicate that we need to send a new
	 * ticket. */
	return 2;
	}
