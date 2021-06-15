bool __netlink_ns_capable(const struct netlink_skb_parms *nsp,
			struct user_namespace *user_ns, int cap)
{
	return ((nsp->flags & NETLINK_SKB_DST) ||
		file_ns_capable(nsp->sk->sk_socket->file, user_ns, cap)) &&
		ns_capable(user_ns, cap);
}
