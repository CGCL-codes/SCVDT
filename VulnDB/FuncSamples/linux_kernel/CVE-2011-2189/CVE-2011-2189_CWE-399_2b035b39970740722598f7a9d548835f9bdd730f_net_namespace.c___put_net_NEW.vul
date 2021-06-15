void __put_net(struct net *net)
{
	/* Cleanup the network namespace in process context */
	unsigned long flags;

	spin_lock_irqsave(&cleanup_list_lock, flags);
	list_add(&net->cleanup_list, &cleanup_list);
	spin_unlock_irqrestore(&cleanup_list_lock, flags);

	queue_work(netns_wq, &net_cleanup_work);
}
