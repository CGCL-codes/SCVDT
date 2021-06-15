static bool generic_new(struct nf_conn *ct, const struct sk_buff *skb,
			unsigned int dataoff, unsigned int *timeouts)
{
	return nf_generic_should_process(nf_ct_protonum(ct));
}
