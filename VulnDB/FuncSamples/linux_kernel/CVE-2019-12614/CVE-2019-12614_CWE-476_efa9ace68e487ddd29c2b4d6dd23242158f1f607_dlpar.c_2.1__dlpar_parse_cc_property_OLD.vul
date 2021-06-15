static struct property *dlpar_parse_cc_property(struct cc_workarea *ccwa)
{
	struct property *prop;
	char *name;
	char *value;

	prop = kzalloc(sizeof(*prop), GFP_KERNEL);
	if (!prop)
		return NULL;

	name = (char *)ccwa + be32_to_cpu(ccwa->name_offset);
	prop->name = kstrdup(name, GFP_KERNEL);

	prop->length = be32_to_cpu(ccwa->prop_length);
	value = (char *)ccwa + be32_to_cpu(ccwa->prop_offset);
	prop->value = kmemdup(value, prop->length, GFP_KERNEL);
	if (!prop->value) {
		dlpar_free_cc_property(prop);
		return NULL;
	}

	return prop;
}
