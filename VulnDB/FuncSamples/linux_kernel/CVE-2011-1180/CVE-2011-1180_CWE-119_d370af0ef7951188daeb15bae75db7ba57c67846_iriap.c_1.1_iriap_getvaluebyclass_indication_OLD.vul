static void iriap_getvaluebyclass_indication(struct iriap_cb *self,
					     struct sk_buff *skb)
{
	struct ias_object *obj;
	struct ias_attrib *attrib;
	int name_len;
	int attr_len;
	char name[IAS_MAX_CLASSNAME + 1];	/* 60 bytes */
	char attr[IAS_MAX_ATTRIBNAME + 1];	/* 60 bytes */
	__u8 *fp;
	int n;

	IRDA_DEBUG(4, "%s()\n", __func__);

	IRDA_ASSERT(self != NULL, return;);
	IRDA_ASSERT(self->magic == IAS_MAGIC, return;);
	IRDA_ASSERT(skb != NULL, return;);

	fp = skb->data;
	n = 1;

	name_len = fp[n++];
	memcpy(name, fp+n, name_len); n+=name_len;
	name[name_len] = '\0';

	attr_len = fp[n++];
	memcpy(attr, fp+n, attr_len); n+=attr_len;
	attr[attr_len] = '\0';

	IRDA_DEBUG(4, "LM-IAS: Looking up %s: %s\n", name, attr);
	obj = irias_find_object(name);

	if (obj == NULL) {
		IRDA_DEBUG(2, "LM-IAS: Object %s not found\n", name);
		iriap_getvaluebyclass_response(self, 0x1235, IAS_CLASS_UNKNOWN,
					       &irias_missing);
		return;
	}
	IRDA_DEBUG(4, "LM-IAS: found %s, id=%d\n", obj->name, obj->id);

	attrib = irias_find_attrib(obj, attr);
	if (attrib == NULL) {
		IRDA_DEBUG(2, "LM-IAS: Attribute %s not found\n", attr);
		iriap_getvaluebyclass_response(self, obj->id,
					       IAS_ATTRIB_UNKNOWN,
					       &irias_missing);
		return;
	}

	/* We have a match; send the value.  */
	iriap_getvaluebyclass_response(self, obj->id, IAS_SUCCESS,
				       attrib->value);
}
