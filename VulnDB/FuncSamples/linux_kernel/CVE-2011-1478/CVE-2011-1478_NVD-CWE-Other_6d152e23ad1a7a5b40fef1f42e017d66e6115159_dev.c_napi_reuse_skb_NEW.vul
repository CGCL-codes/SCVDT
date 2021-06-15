static void napi_reuse_skb(struct napi_struct *napi, struct sk_buff *skb)
{
	__skb_pull(skb, skb_headlen(skb));
	skb_reserve(skb, NET_IP_ALIGN - skb_headroom(skb));
	skb->vlan_tci = 0;
	skb->dev = napi->dev;
	skb->skb_iif = 0;

	napi->skb = skb;
}
