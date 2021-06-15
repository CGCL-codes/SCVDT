void oz_usb_rx(struct oz_pd *pd, struct oz_elt *elt)
{
	struct oz_usb_hdr *usb_hdr = (struct oz_usb_hdr *)(elt + 1);
	struct oz_usb_ctx *usb_ctx;

	spin_lock_bh(&pd->app_lock[OZ_APPID_USB]);
	usb_ctx = (struct oz_usb_ctx *)pd->app_ctx[OZ_APPID_USB];
	if (usb_ctx)
		oz_usb_get(usb_ctx);
	spin_unlock_bh(&pd->app_lock[OZ_APPID_USB]);
	if (usb_ctx == NULL)
		return; /* Context has gone so nothing to do. */
	if (usb_ctx->stopped)
		goto done;
	/* If sequence number is non-zero then check it is not a duplicate.
	 * Zero sequence numbers are always accepted.
	 */
	if (usb_hdr->elt_seq_num != 0) {
		if (((usb_ctx->rx_seq_num - usb_hdr->elt_seq_num) & 0x80) == 0)
			/* Reject duplicate element. */
			goto done;
	}
	usb_ctx->rx_seq_num = usb_hdr->elt_seq_num;
	switch (usb_hdr->type) {
	case OZ_GET_DESC_RSP: {
			struct oz_get_desc_rsp *body =
				(struct oz_get_desc_rsp *)usb_hdr;
			int data_len = elt->length -
					sizeof(struct oz_get_desc_rsp) + 1;
			u16 offs = le16_to_cpu(get_unaligned(&body->offset));
			u16 total_size =
				le16_to_cpu(get_unaligned(&body->total_size));
			oz_dbg(ON, "USB_REQ_GET_DESCRIPTOR - cnf\n");
			oz_hcd_get_desc_cnf(usb_ctx->hport, body->req_id,
					body->rcode, body->data,
					data_len, offs, total_size);
		}
		break;
	case OZ_SET_CONFIG_RSP: {
			struct oz_set_config_rsp *body =
				(struct oz_set_config_rsp *)usb_hdr;
			oz_hcd_control_cnf(usb_ctx->hport, body->req_id,
				body->rcode, NULL, 0);
		}
		break;
	case OZ_SET_INTERFACE_RSP: {
			struct oz_set_interface_rsp *body =
				(struct oz_set_interface_rsp *)usb_hdr;
			oz_hcd_control_cnf(usb_ctx->hport,
				body->req_id, body->rcode, NULL, 0);
		}
		break;
	case OZ_VENDOR_CLASS_RSP: {
			struct oz_vendor_class_rsp *body =
				(struct oz_vendor_class_rsp *)usb_hdr;
			oz_hcd_control_cnf(usb_ctx->hport, body->req_id,
				body->rcode, body->data, elt->length-
				sizeof(struct oz_vendor_class_rsp)+1);
		}
		break;
	case OZ_USB_ENDPOINT_DATA:
		oz_usb_handle_ep_data(usb_ctx, usb_hdr, elt->length);
		break;
	}
done:
	oz_usb_put(usb_ctx);
}
