static void drop_sysctl_table(struct ctl_table_header *header)
{
	struct ctl_dir *parent = header->parent;

	if (--header->nreg)
		return;

	put_links(header);
	start_unregistering(header);
	if (!--header->count)
		kfree_rcu(header, rcu);

	if (parent)
		drop_sysctl_table(&parent->header);
}
