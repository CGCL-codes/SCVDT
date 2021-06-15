int ssl3_get_cert_verify(SSL *s)
	{
	EVP_PKEY *pkey=NULL;
	unsigned char *p;
	int al,ok,ret=0;
	long n;
	int type=0,i,j;
	X509 *peer;
	const EVP_MD *md = NULL;
	EVP_MD_CTX mctx;
	EVP_MD_CTX_init(&mctx);

	n=s->method->ssl_get_message(s,
		SSL3_ST_SR_CERT_VRFY_A,
		SSL3_ST_SR_CERT_VRFY_B,
		-1,
		SSL3_RT_MAX_PLAIN_LENGTH,
		&ok);

	if (!ok) return((int)n);

	if (s->session->peer != NULL)
		{
		peer=s->session->peer;
		pkey=X509_get_pubkey(peer);
		type=X509_certificate_type(peer,pkey);
		}
	else
		{
		peer=NULL;
		pkey=NULL;
		}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_VERIFY)
		{
		s->s3->tmp.reuse_message=1;
		if ((peer != NULL) && (type & EVP_PKT_SIGN))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_MISSING_VERIFY_MESSAGE);
			goto f_err;
			}
		ret=1;
		goto end;
		}

	if (peer == NULL)
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_NO_CLIENT_CERT_RECEIVED);
		al=SSL_AD_UNEXPECTED_MESSAGE;
		goto f_err;
		}

	if (!(type & EVP_PKT_SIGN))
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
		al=SSL_AD_ILLEGAL_PARAMETER;
		goto f_err;
		}

	if (s->s3->change_cipher_spec)
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_CCS_RECEIVED_EARLY);
		al=SSL_AD_UNEXPECTED_MESSAGE;
		goto f_err;
		}

	/* we now have a signature that we need to verify */
	p=(unsigned char *)s->init_msg;
	/* Check for broken implementations of GOST ciphersuites */
	/* If key is GOST and n is exactly 64, it is bare
	 * signature without length field */
	if (n==64 && (pkey->type==NID_id_GostR3410_94 ||
		pkey->type == NID_id_GostR3410_2001) )
		{
		i=64;
		} 
	else 
		{	
		if (SSL_USE_SIGALGS(s))
			{
			int rv = tls12_check_peer_sigalg(&md, s, p, pkey);
			if (rv == -1)
				{
				al = SSL_AD_INTERNAL_ERROR;
				goto f_err;
				}
			else if (rv == 0)
				{
				al = SSL_AD_DECODE_ERROR;
				goto f_err;
				}
#ifdef SSL_DEBUG
fprintf(stderr, "USING TLSv1.2 HASH %s\n", EVP_MD_name(md));
#endif
			p += 2;
			n -= 2;
			}
		n2s(p,i);
		n-=2;
		if (i > n)
			{
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_LENGTH_MISMATCH);
			al=SSL_AD_DECODE_ERROR;
			goto f_err;
			}
    	}
	j=EVP_PKEY_size(pkey);
	if ((i > j) || (n > j) || (n <= 0))
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_WRONG_SIGNATURE_SIZE);
		al=SSL_AD_DECODE_ERROR;
		goto f_err;
		}

	if (SSL_USE_SIGALGS(s))
		{
		long hdatalen = 0;
		void *hdata;
		hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
		if (hdatalen <= 0)
			{
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
			al=SSL_AD_INTERNAL_ERROR;
			goto f_err;
			}
#ifdef SSL_DEBUG
		fprintf(stderr, "Using TLS 1.2 with client verify alg %s\n",
							EVP_MD_name(md));
#endif
		if (!EVP_VerifyInit_ex(&mctx, md, NULL)
			|| !EVP_VerifyUpdate(&mctx, hdata, hdatalen))
			{
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_EVP_LIB);
			al=SSL_AD_INTERNAL_ERROR;
			goto f_err;
			}

		if (EVP_VerifyFinal(&mctx, p , i, pkey) <= 0)
			{
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_BAD_SIGNATURE);
			goto f_err;
			}
		}
	else
#ifndef OPENSSL_NO_RSA 
	if (pkey->type == EVP_PKEY_RSA)
		{
		i=RSA_verify(NID_md5_sha1, s->s3->tmp.cert_verify_md,
			MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH, p, i, 
							pkey->pkey.rsa);
		if (i < 0)
			{
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_BAD_RSA_DECRYPT);
			goto f_err;
			}
		if (i == 0)
			{
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_BAD_RSA_SIGNATURE);
			goto f_err;
			}
		}
	else
#endif
#ifndef OPENSSL_NO_DSA
		if (pkey->type == EVP_PKEY_DSA)
		{
		j=DSA_verify(pkey->save_type,
			&(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]),
			SHA_DIGEST_LENGTH,p,i,pkey->pkey.dsa);
		if (j <= 0)
			{
			/* bad signature */
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,SSL_R_BAD_DSA_SIGNATURE);
			goto f_err;
			}
		}
	else
#endif
#ifndef OPENSSL_NO_ECDSA
		if (pkey->type == EVP_PKEY_EC)
		{
		j=ECDSA_verify(pkey->save_type,
			&(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]),
			SHA_DIGEST_LENGTH,p,i,pkey->pkey.ec);
		if (j <= 0)
			{
			/* bad signature */
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,
			    SSL_R_BAD_ECDSA_SIGNATURE);
			goto f_err;
			}
		}
	else
#endif
	if (pkey->type == NID_id_GostR3410_94 || pkey->type == NID_id_GostR3410_2001)
		{   unsigned char signature[64];
			int idx;
			EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey,NULL);
			EVP_PKEY_verify_init(pctx);
			if (i!=64) {
				fprintf(stderr,"GOST signature length is %d",i);
			}	
			for (idx=0;idx<64;idx++) {
				signature[63-idx]=p[idx];
			}	
			j=EVP_PKEY_verify(pctx,signature,64,s->s3->tmp.cert_verify_md,32);
			EVP_PKEY_CTX_free(pctx);
			if (j<=0) 
				{
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,
					SSL_R_BAD_ECDSA_SIGNATURE);
				goto f_err;
				}	
		}
	else	
		{
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY,ERR_R_INTERNAL_ERROR);
		al=SSL_AD_UNSUPPORTED_CERTIFICATE;
		goto f_err;
		}


	ret=1;
	if (0)
		{
f_err:
		ssl3_send_alert(s,SSL3_AL_FATAL,al);
		}
end:
	if (s->s3->handshake_buffer)
		{
		BIO_free(s->s3->handshake_buffer);
		s->s3->handshake_buffer = NULL;
		s->s3->flags &= ~TLS1_FLAGS_KEEP_HANDSHAKE;
		}
	EVP_MD_CTX_cleanup(&mctx);
	EVP_PKEY_free(pkey);
	return(ret);
	}
