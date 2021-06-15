static int perf_swevent_add(struct perf_event *event, int flags)
{
	struct swevent_htable *swhash = this_cpu_ptr(&swevent_htable);
	struct hw_perf_event *hwc = &event->hw;
	struct hlist_head *head;

	if (is_sampling_event(event)) {
		hwc->last_period = hwc->sample_period;
		perf_swevent_set_period(event);
	}

	hwc->state = !(flags & PERF_EF_START);

	head = find_swevent_head(swhash, event);
	if (!head) {
		/*
		 * We can race with cpu hotplug code. Do not
		 * WARN if the cpu just got unplugged.
		 */
		WARN_ON_ONCE(swhash->online);
		return -EINVAL;
	}

	hlist_add_head_rcu(&event->hlist_entry, head);
	perf_event_update_userpage(event);

	return 0;
}
