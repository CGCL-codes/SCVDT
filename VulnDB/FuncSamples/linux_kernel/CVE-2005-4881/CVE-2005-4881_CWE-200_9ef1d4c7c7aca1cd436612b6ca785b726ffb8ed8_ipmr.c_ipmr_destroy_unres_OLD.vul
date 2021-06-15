static void ipmr_destroy_unres(struct mfc_cache *c)
{
	struct sk_buff *skb;

	atomic_dec(&cache_resolve_queue_len);

	while((skb=skb_dequeue(&c->mfc_un.unres.unresolved))) {
		if (skb->nh.iph->version == 0) {
			struct nlmsghdr *nlh = (struct nlmsghdr *)skb_pull(skb, sizeof(struct iphdr));
			nlh->nlmsg_type = NLMSG_ERROR;
			nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
			skb_trim(skb, nlh->nlmsg_len);
			((struct nlmsgerr*)NLMSG_DATA(nlh))->error = -ETIMEDOUT;
			netlink_unicast(rtnl, skb, NETLINK_CB(skb).dst_pid, MSG_DONTWAIT);
		} else
			kfree_skb(skb);
	}

	kmem_cache_free(mrt_cachep, c);
}
