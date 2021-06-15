static void do_free_upto(BIO *f, BIO *upto)
{
    if (upto) {
        BIO *tbio;
        do {
            tbio = BIO_pop(f);
            BIO_free(f);
            f = tbio;
        }
        while (f && f != upto);
    } else
        BIO_free_all(f);
}
