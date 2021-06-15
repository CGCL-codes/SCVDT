asmlinkage long compat_sys_pselect6(int n, compat_ulong_t __user *inp,
	compat_ulong_t __user *outp, compat_ulong_t __user *exp,
	struct compat_timespec __user *tsp, void __user *sig)
{
	compat_size_t sigsetsize = 0;
	compat_uptr_t up = 0;

	if (sig) {
		if (!access_ok(VERIFY_READ, sig,
				sizeof(compat_uptr_t)+sizeof(compat_size_t)) ||
		    	__get_user(up, (compat_uptr_t __user *)sig) ||
		    	__get_user(sigsetsize,
				(compat_size_t __user *)(sig+sizeof(up))))
			return -EFAULT;
	}
	return compat_sys_pselect7(n, inp, outp, exp, tsp, compat_ptr(up),
					sigsetsize);
}
