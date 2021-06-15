static struct fsnotify_group *inotify_new_group(struct user_struct *user, unsigned int max_events)
{
	struct fsnotify_group *group;

	group = fsnotify_alloc_group(&inotify_fsnotify_ops);
	if (IS_ERR(group))
		return group;

	group->max_events = max_events;

	spin_lock_init(&group->inotify_data.idr_lock);
	idr_init(&group->inotify_data.idr);
	group->inotify_data.last_wd = 0;
	group->inotify_data.user = user;
	group->inotify_data.fa = NULL;

	return group;
}
