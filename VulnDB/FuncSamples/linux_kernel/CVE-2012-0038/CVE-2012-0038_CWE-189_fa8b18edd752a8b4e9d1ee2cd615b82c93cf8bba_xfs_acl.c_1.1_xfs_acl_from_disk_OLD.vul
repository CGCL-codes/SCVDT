STATIC struct posix_acl *
xfs_acl_from_disk(struct xfs_acl *aclp)
{
	struct posix_acl_entry *acl_e;
	struct posix_acl *acl;
	struct xfs_acl_entry *ace;
	int count, i;

	count = be32_to_cpu(aclp->acl_cnt);

	acl = posix_acl_alloc(count, GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < count; i++) {
		acl_e = &acl->a_entries[i];
		ace = &aclp->acl_entry[i];

		/*
		 * The tag is 32 bits on disk and 16 bits in core.
		 *
		 * Because every access to it goes through the core
		 * format first this is not a problem.
		 */
		acl_e->e_tag = be32_to_cpu(ace->ae_tag);
		acl_e->e_perm = be16_to_cpu(ace->ae_perm);

		switch (acl_e->e_tag) {
		case ACL_USER:
		case ACL_GROUP:
			acl_e->e_id = be32_to_cpu(ace->ae_id);
			break;
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			acl_e->e_id = ACL_UNDEFINED_ID;
			break;
		default:
			goto fail;
		}
	}
	return acl;

fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}
