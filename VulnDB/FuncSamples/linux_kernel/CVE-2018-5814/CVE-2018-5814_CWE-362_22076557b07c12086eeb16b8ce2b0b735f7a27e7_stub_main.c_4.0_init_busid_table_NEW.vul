static void init_busid_table(void)
{
	int i;

	/*
	 * This also sets the bus_table[i].status to
	 * STUB_BUSID_OTHER, which is 0.
	 */
	memset(busid_table, 0, sizeof(busid_table));

	spin_lock_init(&busid_table_lock);

	for (i = 0; i < MAX_BUSID; i++)
		spin_lock_init(&busid_table[i].busid_lock);
}
