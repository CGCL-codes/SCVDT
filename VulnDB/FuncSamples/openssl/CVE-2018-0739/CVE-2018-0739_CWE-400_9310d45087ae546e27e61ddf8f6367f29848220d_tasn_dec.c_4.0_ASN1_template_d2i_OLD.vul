int ASN1_template_d2i(ASN1_VALUE **pval,
                      const unsigned char **in, long len,
                      const ASN1_TEMPLATE *tt)
{
    ASN1_TLC c;
    asn1_tlc_clear_nc(&c);
    return asn1_template_ex_d2i(pval, in, len, tt, 0, &c);
}
