void perf_event_disable(struct perf_event *event)
{
	struct perf_event_context *ctx;

	ctx = perf_event_ctx_lock(event);
	_perf_event_disable(event);
	perf_event_ctx_unlock(event, ctx);
}
