int unshare_userns(unsigned long unshare_flags, struct cred **new_cred)
{
	struct cred *cred;

	if (!(unshare_flags & CLONE_NEWUSER))
		return 0;

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	*new_cred = cred;
	return create_user_ns(cred);
}
