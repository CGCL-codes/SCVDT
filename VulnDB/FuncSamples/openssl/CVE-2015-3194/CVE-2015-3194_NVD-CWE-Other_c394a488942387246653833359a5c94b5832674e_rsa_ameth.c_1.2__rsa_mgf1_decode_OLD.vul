static X509_ALGOR *rsa_mgf1_decode(X509_ALGOR *alg)
{
    const unsigned char *p;
    int plen;
    if (alg == NULL)
        return NULL;
    if (OBJ_obj2nid(alg->algorithm) != NID_mgf1)
        return NULL;
    if (alg->parameter->type != V_ASN1_SEQUENCE)
        return NULL;

    p = alg->parameter->value.sequence->data;
    plen = alg->parameter->value.sequence->length;
    return d2i_X509_ALGOR(NULL, &p, plen);
}
