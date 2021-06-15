static void __net_random_once_deferred(struct work_struct *w)
{
	struct __net_random_once_work *work =
		container_of(w, struct __net_random_once_work, work);
	BUG_ON(!static_key_enabled(work->key));
	static_key_slow_dec(work->key);
	kfree(work);
}
