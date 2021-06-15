static __inline__ int cbq_dump_ovl(struct sk_buff *skb, struct cbq_class *cl)
{
	unsigned char	 *b = skb->tail;
	struct tc_cbq_ovl opt;

	opt.strategy = cl->ovl_strategy;
	opt.priority2 = cl->priority2+1;
	opt.penalty = (cl->penalty*1000)/HZ;
	RTA_PUT(skb, TCA_CBQ_OVL_STRATEGY, sizeof(opt), &opt);
	return skb->len;

rtattr_failure:
	skb_trim(skb, b - skb->data);
	return -1;
}
