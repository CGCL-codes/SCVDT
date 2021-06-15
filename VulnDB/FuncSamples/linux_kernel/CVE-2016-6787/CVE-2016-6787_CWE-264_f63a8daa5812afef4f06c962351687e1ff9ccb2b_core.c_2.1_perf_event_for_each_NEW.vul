static void perf_event_for_each(struct perf_event *event,
				  void (*func)(struct perf_event *))
{
	struct perf_event_context *ctx = event->ctx;
	struct perf_event *sibling;

	lockdep_assert_held(&ctx->mutex);

	event = event->group_leader;

	perf_event_for_each_child(event, func);
	list_for_each_entry(sibling, &event->sibling_list, group_entry)
		perf_event_for_each_child(sibling, func);
}
