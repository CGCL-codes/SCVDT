void perf_pmu_migrate_context(struct pmu *pmu, int src_cpu, int dst_cpu)
{
	struct perf_event_context *src_ctx;
	struct perf_event_context *dst_ctx;
	struct perf_event *event, *tmp;
	LIST_HEAD(events);

	src_ctx = &per_cpu_ptr(pmu->pmu_cpu_context, src_cpu)->ctx;
	dst_ctx = &per_cpu_ptr(pmu->pmu_cpu_context, dst_cpu)->ctx;

	mutex_lock(&src_ctx->mutex);
	list_for_each_entry_safe(event, tmp, &src_ctx->event_list,
				 event_entry) {
		perf_remove_from_context(event, false);
		unaccount_event_cpu(event, src_cpu);
		put_ctx(src_ctx);
		list_add(&event->migrate_entry, &events);
	}
	mutex_unlock(&src_ctx->mutex);

	synchronize_rcu();

	mutex_lock(&dst_ctx->mutex);
	list_for_each_entry_safe(event, tmp, &events, migrate_entry) {
		list_del(&event->migrate_entry);
		if (event->state >= PERF_EVENT_STATE_OFF)
			event->state = PERF_EVENT_STATE_INACTIVE;
		account_event_cpu(event, dst_cpu);
		perf_install_in_context(dst_ctx, event, dst_cpu);
		get_ctx(dst_ctx);
	}
	mutex_unlock(&dst_ctx->mutex);
}
