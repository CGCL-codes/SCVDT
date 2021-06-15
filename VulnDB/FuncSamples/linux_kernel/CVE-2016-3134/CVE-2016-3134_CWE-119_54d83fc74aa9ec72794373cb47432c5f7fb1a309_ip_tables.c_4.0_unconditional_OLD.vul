static inline bool unconditional(const struct ipt_ip *ip)
{
	static const struct ipt_ip uncond;

	return memcmp(ip, &uncond, sizeof(uncond)) == 0;
#undef FWINV
}
