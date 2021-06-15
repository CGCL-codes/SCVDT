static void do_init_timer(struct timer_list *timer, unsigned int flags,
			  const char *name, struct lock_class_key *key)
{
	timer->entry.pprev = NULL;
	timer->flags = flags | raw_smp_processor_id();
	lockdep_init_map(&timer->lockdep_map, name, key, 0);
}
