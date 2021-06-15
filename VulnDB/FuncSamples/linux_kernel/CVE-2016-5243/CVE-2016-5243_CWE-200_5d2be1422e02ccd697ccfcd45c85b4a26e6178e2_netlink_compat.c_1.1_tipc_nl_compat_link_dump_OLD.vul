static int tipc_nl_compat_link_dump(struct tipc_nl_compat_msg *msg,
				    struct nlattr **attrs)
{
	struct nlattr *link[TIPC_NLA_LINK_MAX + 1];
	struct tipc_link_info link_info;
	int err;

	if (!attrs[TIPC_NLA_LINK])
		return -EINVAL;

	err = nla_parse_nested(link, TIPC_NLA_LINK_MAX, attrs[TIPC_NLA_LINK],
			       NULL);
	if (err)
		return err;

	link_info.dest = nla_get_flag(link[TIPC_NLA_LINK_DEST]);
	link_info.up = htonl(nla_get_flag(link[TIPC_NLA_LINK_UP]));
	strcpy(link_info.str, nla_data(link[TIPC_NLA_LINK_NAME]));

	return tipc_add_tlv(msg->rep, TIPC_TLV_LINK_INFO,
			    &link_info, sizeof(link_info));
}
