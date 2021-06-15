static void perf_event_init_cpu(int cpu)
{
	struct swevent_htable *swhash = &per_cpu(swevent_htable, cpu);

	mutex_lock(&swhash->hlist_mutex);
	swhash->online = true;
	if (swhash->hlist_refcount > 0) {
		struct swevent_hlist *hlist;

		hlist = kzalloc_node(sizeof(*hlist), GFP_KERNEL, cpu_to_node(cpu));
		WARN_ON(!hlist);
		rcu_assign_pointer(swhash->swevent_hlist, hlist);
	}
	mutex_unlock(&swhash->hlist_mutex);
}
