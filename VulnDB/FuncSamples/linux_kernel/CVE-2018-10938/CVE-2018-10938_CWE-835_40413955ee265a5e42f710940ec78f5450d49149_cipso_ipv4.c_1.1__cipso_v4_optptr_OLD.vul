unsigned char *cipso_v4_optptr(const struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	unsigned char *optptr = (unsigned char *)&(ip_hdr(skb)[1]);
	int optlen;
	int taglen;

	for (optlen = iph->ihl*4 - sizeof(struct iphdr); optlen > 0; ) {
		if (optptr[0] == IPOPT_CIPSO)
			return optptr;
		taglen = optptr[1];
		optlen -= taglen;
		optptr += taglen;
	}

	return NULL;
}
