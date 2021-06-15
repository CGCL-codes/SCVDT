static int perf_event_read_group(struct perf_event *event,
				   u64 read_format, char __user *buf)
{
	struct perf_event *leader = event->group_leader, *sub;
	int n = 0, size = 0, ret = -EFAULT;
	struct perf_event_context *ctx = leader->ctx;
	u64 values[5];
	u64 count, enabled, running;

	mutex_lock(&ctx->mutex);
	count = perf_event_read_value(leader, &enabled, &running);

	values[n++] = 1 + leader->nr_siblings;
	if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED)
		values[n++] = enabled;
	if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING)
		values[n++] = running;
	values[n++] = count;
	if (read_format & PERF_FORMAT_ID)
		values[n++] = primary_event_id(leader);

	size = n * sizeof(u64);

	if (copy_to_user(buf, values, size))
		goto unlock;

	ret = size;

	list_for_each_entry(sub, &leader->sibling_list, group_entry) {
		n = 0;

		values[n++] = perf_event_read_value(sub, &enabled, &running);
		if (read_format & PERF_FORMAT_ID)
			values[n++] = primary_event_id(sub);

		size = n * sizeof(u64);

		if (copy_to_user(buf + ret, values, size)) {
			ret = -EFAULT;
			goto unlock;
		}

		ret += size;
	}
unlock:
	mutex_unlock(&ctx->mutex);

	return ret;
}
