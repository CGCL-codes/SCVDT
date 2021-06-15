static inline bool unconditional(const struct ip6t_entry *e)
{
	static const struct ip6t_ip6 uncond;

	return e->target_offset == sizeof(struct ip6t_entry) &&
	       memcmp(&e->ipv6, &uncond, sizeof(uncond)) == 0;
}
