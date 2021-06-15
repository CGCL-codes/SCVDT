static inline bool unconditional(const struct arpt_entry *e)
{
	static const struct arpt_arp uncond;

	return e->target_offset == sizeof(struct arpt_entry) &&
	       memcmp(&e->arp, &uncond, sizeof(uncond)) == 0;
}
