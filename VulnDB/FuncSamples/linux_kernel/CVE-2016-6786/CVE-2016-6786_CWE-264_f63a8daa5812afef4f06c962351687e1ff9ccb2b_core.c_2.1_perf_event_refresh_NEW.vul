int perf_event_refresh(struct perf_event *event, int refresh)
{
	struct perf_event_context *ctx;
	int ret;

	ctx = perf_event_ctx_lock(event);
	ret = _perf_event_refresh(event, refresh);
	perf_event_ctx_unlock(event, ctx);

	return ret;
}
