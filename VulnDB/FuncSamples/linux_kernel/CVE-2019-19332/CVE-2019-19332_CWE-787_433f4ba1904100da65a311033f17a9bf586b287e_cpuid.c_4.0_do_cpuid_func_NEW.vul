static int do_cpuid_func(struct kvm_cpuid_entry2 *entry, u32 func,
			 int *nent, int maxnent, unsigned int type)
{
	if (*nent >= maxnent)
		return -E2BIG;

	if (type == KVM_GET_EMULATED_CPUID)
		return __do_cpuid_func_emulated(entry, func, nent, maxnent);

	return __do_cpuid_func(entry, func, nent, maxnent);
}
