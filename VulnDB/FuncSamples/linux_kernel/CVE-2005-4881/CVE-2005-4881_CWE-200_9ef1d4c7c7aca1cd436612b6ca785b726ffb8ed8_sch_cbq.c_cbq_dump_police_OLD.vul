static __inline__ int cbq_dump_police(struct sk_buff *skb, struct cbq_class *cl)
{
	unsigned char	 *b = skb->tail;
	struct tc_cbq_police opt;

	if (cl->police) {
		opt.police = cl->police;
		RTA_PUT(skb, TCA_CBQ_POLICE, sizeof(opt), &opt);
	}
	return skb->len;

rtattr_failure:
	skb_trim(skb, b - skb->data);
	return -1;
}
