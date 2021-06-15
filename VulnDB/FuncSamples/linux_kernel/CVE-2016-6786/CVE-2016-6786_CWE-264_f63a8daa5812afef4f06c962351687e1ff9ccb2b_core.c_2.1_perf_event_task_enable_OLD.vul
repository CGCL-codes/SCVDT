int perf_event_task_enable(void)
{
	struct perf_event *event;

	mutex_lock(&current->perf_event_mutex);
	list_for_each_entry(event, &current->perf_event_list, owner_entry)
		perf_event_for_each_child(event, perf_event_enable);
	mutex_unlock(&current->perf_event_mutex);

	return 0;
}
