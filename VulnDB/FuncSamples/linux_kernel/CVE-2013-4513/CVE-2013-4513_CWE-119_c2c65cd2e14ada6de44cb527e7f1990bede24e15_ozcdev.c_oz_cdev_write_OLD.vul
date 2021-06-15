static ssize_t oz_cdev_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *fpos)
{
	struct oz_pd *pd;
	struct oz_elt_buf *eb;
	struct oz_elt_info *ei;
	struct oz_elt *elt;
	struct oz_app_hdr *app_hdr;
	struct oz_serial_ctx *ctx;

	spin_lock_bh(&g_cdev.lock);
	pd = g_cdev.active_pd;
	if (pd)
		oz_pd_get(pd);
	spin_unlock_bh(&g_cdev.lock);
	if (pd == NULL)
		return -ENXIO;
	if (!(pd->state & OZ_PD_S_CONNECTED))
		return -EAGAIN;
	eb = &pd->elt_buff;
	ei = oz_elt_info_alloc(eb);
	if (ei == NULL) {
		count = 0;
		goto out;
	}
	elt = (struct oz_elt *)ei->data;
	app_hdr = (struct oz_app_hdr *)(elt+1);
	elt->length = sizeof(struct oz_app_hdr) + count;
	elt->type = OZ_ELT_APP_DATA;
	ei->app_id = OZ_APPID_SERIAL;
	ei->length = elt->length + sizeof(struct oz_elt);
	app_hdr->app_id = OZ_APPID_SERIAL;
	if (copy_from_user(app_hdr+1, buf, count))
		goto out;
	spin_lock_bh(&pd->app_lock[OZ_APPID_USB-1]);
	ctx = (struct oz_serial_ctx *)pd->app_ctx[OZ_APPID_SERIAL-1];
	if (ctx) {
		app_hdr->elt_seq_num = ctx->tx_seq_num++;
		if (ctx->tx_seq_num == 0)
			ctx->tx_seq_num = 1;
		spin_lock(&eb->lock);
		if (oz_queue_elt_info(eb, 0, 0, ei) == 0)
			ei = NULL;
		spin_unlock(&eb->lock);
	}
	spin_unlock_bh(&pd->app_lock[OZ_APPID_USB-1]);
out:
	if (ei) {
		count = 0;
		spin_lock_bh(&eb->lock);
		oz_elt_info_free(eb, ei);
		spin_unlock_bh(&eb->lock);
	}
	oz_pd_put(pd);
	return count;
}
