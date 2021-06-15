static int hid_debug_events_release(struct inode *inode, struct file *file)
{
	struct hid_debug_list *list = file->private_data;
	unsigned long flags;

	spin_lock_irqsave(&list->hdev->debug_list_lock, flags);
	list_del(&list->node);
	spin_unlock_irqrestore(&list->hdev->debug_list_lock, flags);
	kfifo_free(&list->hid_debug_fifo);
	kfree(list);

	return 0;
}
