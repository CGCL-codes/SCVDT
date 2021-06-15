static int neigh_fill_info(struct sk_buff *skb, struct neighbour *n,
			   u32 pid, u32 seq, int event, unsigned int flags)
{
	unsigned long now = jiffies;
	unsigned char *b = skb->tail;
	struct nda_cacheinfo ci;
	int locked = 0;
	u32 probes;
	struct nlmsghdr *nlh = NLMSG_NEW(skb, pid, seq, event,
					 sizeof(struct ndmsg), flags);
	struct ndmsg *ndm = NLMSG_DATA(nlh);

	ndm->ndm_family	 = n->ops->family;
	ndm->ndm_pad1    = 0;
	ndm->ndm_pad2    = 0;
	ndm->ndm_flags	 = n->flags;
	ndm->ndm_type	 = n->type;
	ndm->ndm_ifindex = n->dev->ifindex;
	RTA_PUT(skb, NDA_DST, n->tbl->key_len, n->primary_key);
	read_lock_bh(&n->lock);
	locked		 = 1;
	ndm->ndm_state	 = n->nud_state;
	if (n->nud_state & NUD_VALID)
		RTA_PUT(skb, NDA_LLADDR, n->dev->addr_len, n->ha);
	ci.ndm_used	 = now - n->used;
	ci.ndm_confirmed = now - n->confirmed;
	ci.ndm_updated	 = now - n->updated;
	ci.ndm_refcnt	 = atomic_read(&n->refcnt) - 1;
	probes = atomic_read(&n->probes);
	read_unlock_bh(&n->lock);
	locked		 = 0;
	RTA_PUT(skb, NDA_CACHEINFO, sizeof(ci), &ci);
	RTA_PUT(skb, NDA_PROBES, sizeof(probes), &probes);
	nlh->nlmsg_len	 = skb->tail - b;
	return skb->len;

nlmsg_failure:
rtattr_failure:
	if (locked)
		read_unlock_bh(&n->lock);
	skb_trim(skb, b - skb->data);
	return -1;
}
