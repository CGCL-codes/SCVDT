static int add_match_busid(char *busid)
{
	int i;
	int ret = -1;

	spin_lock(&busid_table_lock);
	/* already registered? */
	if (get_busid_idx(busid) >= 0) {
		ret = 0;
		goto out;
	}

	for (i = 0; i < MAX_BUSID; i++) {
		spin_lock(&busid_table[i].busid_lock);
		if (!busid_table[i].name[0]) {
			strlcpy(busid_table[i].name, busid, BUSID_SIZE);
			if ((busid_table[i].status != STUB_BUSID_ALLOC) &&
			    (busid_table[i].status != STUB_BUSID_REMOV))
				busid_table[i].status = STUB_BUSID_ADDED;
			ret = 0;
			spin_unlock(&busid_table[i].busid_lock);
			break;
		}
		spin_unlock(&busid_table[i].busid_lock);
	}

out:
	spin_unlock(&busid_table_lock);

	return ret;
}
