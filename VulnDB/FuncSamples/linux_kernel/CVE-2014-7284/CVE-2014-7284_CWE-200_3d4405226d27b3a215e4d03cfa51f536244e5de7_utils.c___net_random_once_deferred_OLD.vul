static void __net_random_once_deferred(struct work_struct *w)
{
	struct __net_random_once_work *work =
		container_of(w, struct __net_random_once_work, work);
	if (!static_key_enabled(work->key))
		static_key_slow_inc(work->key);
	kfree(work);
}
