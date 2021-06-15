static int ssl_srp_server_param_cb(SSL *s, int *ad, void *arg)
{
    srpsrvparm *p = (srpsrvparm *) arg;
    int ret = SSL3_AL_FATAL;

    if (p->login == NULL && p->user == NULL) {
        p->login = SSL_get_srp_username(s);
        BIO_printf(bio_err, "SRP username = \"%s\"\n", p->login);
        return (-1);
    }

    if (p->user == NULL) {
        BIO_printf(bio_err, "User %s doesn't exist\n", p->login);
        goto err;
    }

    if (SSL_set_srp_server_param
        (s, p->user->N, p->user->g, p->user->s, p->user->v,
         p->user->info) < 0) {
        *ad = SSL_AD_INTERNAL_ERROR;
        goto err;
    }
    BIO_printf(bio_err,
               "SRP parameters set: username = \"%s\" info=\"%s\" \n",
               p->login, p->user->info);
    ret = SSL_ERROR_NONE;

err:
    SRP_user_pwd_free(p->user);
    p->user = NULL;
    p->login = NULL;
    return ret;
}
