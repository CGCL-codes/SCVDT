static inline int shmem_acct_size(unsigned long flags, loff_t size)
{
	return (flags & VM_ACCOUNT)?
		security_vm_enough_memory(VM_ACCT(size)): 0;
}
