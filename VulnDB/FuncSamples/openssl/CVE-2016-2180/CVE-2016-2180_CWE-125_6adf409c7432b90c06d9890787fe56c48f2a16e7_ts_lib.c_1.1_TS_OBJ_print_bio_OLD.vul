int TS_OBJ_print_bio(BIO *bio, const ASN1_OBJECT *obj)
{
    char obj_txt[128];

    int len = OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);
    BIO_write(bio, obj_txt, len);
    BIO_write(bio, "\n", 1);

    return 1;
}
