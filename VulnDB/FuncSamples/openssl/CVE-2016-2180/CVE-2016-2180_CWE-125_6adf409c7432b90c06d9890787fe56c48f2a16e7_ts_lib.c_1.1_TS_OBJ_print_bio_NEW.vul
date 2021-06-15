int TS_OBJ_print_bio(BIO *bio, const ASN1_OBJECT *obj)
{
    char obj_txt[128];

    OBJ_obj2txt(obj_txt, sizeof(obj_txt), obj, 0);
    BIO_printf(bio, "%s\n", obj_txt);

    return 1;
}
