int perf_event_task_enable(void)
{
	struct perf_event_context *ctx;
	struct perf_event *event;

	mutex_lock(&current->perf_event_mutex);
	list_for_each_entry(event, &current->perf_event_list, owner_entry) {
		ctx = perf_event_ctx_lock(event);
		perf_event_for_each_child(event, _perf_event_enable);
		perf_event_ctx_unlock(event, ctx);
	}
	mutex_unlock(&current->perf_event_mutex);

	return 0;
}
