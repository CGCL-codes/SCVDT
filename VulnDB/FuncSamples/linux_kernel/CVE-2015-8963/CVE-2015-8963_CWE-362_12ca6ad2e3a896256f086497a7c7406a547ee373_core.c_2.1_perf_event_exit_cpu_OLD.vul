static void perf_event_exit_cpu(int cpu)
{
	struct swevent_htable *swhash = &per_cpu(swevent_htable, cpu);

	perf_event_exit_cpu_context(cpu);

	mutex_lock(&swhash->hlist_mutex);
	swhash->online = false;
	swevent_hlist_release(swhash);
	mutex_unlock(&swhash->hlist_mutex);
}
