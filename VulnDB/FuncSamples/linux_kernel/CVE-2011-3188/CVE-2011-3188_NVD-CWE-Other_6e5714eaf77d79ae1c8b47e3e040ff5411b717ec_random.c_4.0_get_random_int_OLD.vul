unsigned int get_random_int(void)
{
	struct keydata *keyptr;
	__u32 *hash = get_cpu_var(get_random_int_hash);
	int ret;

	keyptr = get_keyptr();
	hash[0] += current->pid + jiffies + get_cycles();

	ret = half_md4_transform(hash, keyptr->secret);
	put_cpu_var(get_random_int_hash);

	return ret;
}
