int wait_for_key_construction(struct key *key, bool intr)
{
	int ret;

	ret = wait_on_bit(&key->flags, KEY_FLAG_USER_CONSTRUCT,
			  intr ? TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE);
	if (ret)
		return -ERESTARTSYS;
	ret = key_read_state(key);
	if (ret < 0)
		return ret;
	return key_validate(key);
}
