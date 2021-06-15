int perf_event_overflow(struct perf_event *event,
			  struct perf_sample_data *data,
			  struct pt_regs *regs)
{
	return __perf_event_overflow(event, 1, data, regs);
}
