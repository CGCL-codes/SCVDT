static int hash_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct hash_ctx *ctx = ask->private;
	struct ahash_request *req = &ctx->req;
	char state[crypto_ahash_statesize(crypto_ahash_reqtfm(req))];
	struct sock *sk2;
	struct alg_sock *ask2;
	struct hash_ctx *ctx2;
	int err;

	err = crypto_ahash_export(req, state);
	if (err)
		return err;

	err = af_alg_accept(ask->parent, newsock);
	if (err)
		return err;

	sk2 = newsock->sk;
	ask2 = alg_sk(sk2);
	ctx2 = ask2->private;
	ctx2->more = 1;

	err = crypto_ahash_import(&ctx2->req, state);
	if (err) {
		sock_orphan(sk2);
		sock_put(sk2);
	}

	return err;
}
