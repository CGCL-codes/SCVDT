static inline bool unconditional(const struct ip6t_ip6 *ipv6)
{
	static const struct ip6t_ip6 uncond;

	return memcmp(ipv6, &uncond, sizeof(uncond)) == 0;
}
