int perf_event_refresh(struct perf_event *event, int refresh)
{
	/*
	 * not supported on inherited events
	 */
	if (event->attr.inherit || !is_sampling_event(event))
		return -EINVAL;

	atomic_add(refresh, &event->event_limit);
	perf_event_enable(event);

	return 0;
}
