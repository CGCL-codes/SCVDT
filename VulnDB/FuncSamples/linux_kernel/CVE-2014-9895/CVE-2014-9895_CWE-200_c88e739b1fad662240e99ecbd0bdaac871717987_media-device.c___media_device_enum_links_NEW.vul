static long __media_device_enum_links(struct media_device *mdev,
				      struct media_links_enum *links)
{
	struct media_entity *entity;

	entity = find_entity(mdev, links->entity);
	if (entity == NULL)
		return -EINVAL;

	if (links->pads) {
		unsigned int p;

		for (p = 0; p < entity->num_pads; p++) {
			struct media_pad_desc pad;

			memset(&pad, 0, sizeof(pad));
			media_device_kpad_to_upad(&entity->pads[p], &pad);
			if (copy_to_user(&links->pads[p], &pad, sizeof(pad)))
				return -EFAULT;
		}
	}

	if (links->links) {
		struct media_link_desc __user *ulink;
		unsigned int l;

		for (l = 0, ulink = links->links; l < entity->num_links; l++) {
			struct media_link_desc link;

			/* Ignore backlinks. */
			if (entity->links[l].source->entity != entity)
				continue;

			memset(&link, 0, sizeof(link));
			media_device_kpad_to_upad(entity->links[l].source,
						  &link.source);
			media_device_kpad_to_upad(entity->links[l].sink,
						  &link.sink);
			link.flags = entity->links[l].flags;
			if (copy_to_user(ulink, &link, sizeof(*ulink)))
				return -EFAULT;
			ulink++;
		}
	}

	return 0;
}
