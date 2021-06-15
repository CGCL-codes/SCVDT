static int netlbl_cipsov4_add_common(struct genl_info *info,
				     struct cipso_v4_doi *doi_def)
{
	struct nlattr *nla;
	int nla_rem;
	u32 iter = 0;

	doi_def->doi = nla_get_u32(info->attrs[NLBL_CIPSOV4_A_DOI]);

	if (nla_validate_nested(info->attrs[NLBL_CIPSOV4_A_TAGLST],
				NLBL_CIPSOV4_A_MAX,
				netlbl_cipsov4_genl_policy) != 0)
		return -EINVAL;

	nla_for_each_nested(nla, info->attrs[NLBL_CIPSOV4_A_TAGLST], nla_rem)
		if (nla->nla_type == NLBL_CIPSOV4_A_TAG) {
			if (iter >= CIPSO_V4_TAG_MAXCNT)
				return -EINVAL;
			doi_def->tags[iter++] = nla_get_u8(nla);
		}
	while (iter < CIPSO_V4_TAG_MAXCNT)
		doi_def->tags[iter++] = CIPSO_V4_TAG_INVALID;

	return 0;
}
