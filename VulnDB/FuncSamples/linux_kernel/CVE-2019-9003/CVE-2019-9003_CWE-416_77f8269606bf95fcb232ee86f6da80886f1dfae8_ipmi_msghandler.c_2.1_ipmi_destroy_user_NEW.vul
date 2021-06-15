int ipmi_destroy_user(struct ipmi_user *user)
{
	_ipmi_destroy_user(user);

	kref_put(&user->refcount, free_user);

	return 0;
}
