static __poll_t hid_debug_events_poll(struct file *file, poll_table *wait)
{
	struct hid_debug_list *list = file->private_data;

	poll_wait(file, &list->hdev->debug_wait, wait);
	if (!kfifo_is_empty(&list->hid_debug_fifo))
		return EPOLLIN | EPOLLRDNORM;
	if (!list->hdev->debug)
		return EPOLLERR | EPOLLHUP;
	return 0;
}
