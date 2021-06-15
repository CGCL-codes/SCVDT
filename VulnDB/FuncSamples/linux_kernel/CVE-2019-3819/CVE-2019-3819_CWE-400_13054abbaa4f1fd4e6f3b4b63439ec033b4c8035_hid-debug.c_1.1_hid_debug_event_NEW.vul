void hid_debug_event(struct hid_device *hdev, char *buf)
{
	struct hid_debug_list *list;
	unsigned long flags;

	spin_lock_irqsave(&hdev->debug_list_lock, flags);
	list_for_each_entry(list, &hdev->debug_list, node)
		kfifo_in(&list->hid_debug_fifo, buf, strlen(buf));
	spin_unlock_irqrestore(&hdev->debug_list_lock, flags);

	wake_up_interruptible(&hdev->debug_wait);
}
