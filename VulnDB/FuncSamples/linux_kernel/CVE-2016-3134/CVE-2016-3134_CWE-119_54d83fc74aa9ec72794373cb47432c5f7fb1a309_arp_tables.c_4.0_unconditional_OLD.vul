static inline bool unconditional(const struct arpt_arp *arp)
{
	static const struct arpt_arp uncond;

	return memcmp(arp, &uncond, sizeof(uncond)) == 0;
}
