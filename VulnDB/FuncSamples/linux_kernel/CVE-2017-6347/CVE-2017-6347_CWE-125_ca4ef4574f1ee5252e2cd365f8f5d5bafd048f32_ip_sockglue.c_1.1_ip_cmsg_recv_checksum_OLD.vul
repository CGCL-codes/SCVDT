static void ip_cmsg_recv_checksum(struct msghdr *msg, struct sk_buff *skb,
				  int tlen, int offset)
{
	__wsum csum = skb->csum;

	if (skb->ip_summed != CHECKSUM_COMPLETE)
		return;

	if (offset != 0)
		csum = csum_sub(csum,
				csum_partial(skb_transport_header(skb) + tlen,
					     offset, 0));

	put_cmsg(msg, SOL_IP, IP_CHECKSUM, sizeof(__wsum), &csum);
}
