static long media_device_enum_entities(struct media_device *mdev,
				       struct media_entity_desc __user *uent)
{
	struct media_entity *ent;
	struct media_entity_desc u_ent;

	if (copy_from_user(&u_ent.id, &uent->id, sizeof(u_ent.id)))
		return -EFAULT;

	ent = find_entity(mdev, u_ent.id);

	if (ent == NULL)
		return -EINVAL;

	u_ent.id = ent->id;
	if (ent->name) {
		strncpy(u_ent.name, ent->name, sizeof(u_ent.name));
		u_ent.name[sizeof(u_ent.name) - 1] = '\0';
	} else {
		memset(u_ent.name, 0, sizeof(u_ent.name));
	}
	u_ent.type = ent->type;
	u_ent.revision = ent->revision;
	u_ent.flags = ent->flags;
	u_ent.group_id = ent->group_id;
	u_ent.pads = ent->num_pads;
	u_ent.links = ent->num_links - ent->num_backlinks;
	memcpy(&u_ent.raw, &ent->info, sizeof(ent->info));
	if (copy_to_user(uent, &u_ent, sizeof(u_ent)))
		return -EFAULT;
	return 0;
}
