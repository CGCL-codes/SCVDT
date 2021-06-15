static int komeda_wb_connector_add(struct komeda_kms_dev *kms,
				   struct komeda_crtc *kcrtc)
{
	struct komeda_dev *mdev = kms->base.dev_private;
	struct komeda_wb_connector *kwb_conn;
	struct drm_writeback_connector *wb_conn;
	u32 *formats, n_formats = 0;
	int err;

	if (!kcrtc->master->wb_layer)
		return 0;

	kwb_conn = kzalloc(sizeof(*kwb_conn), GFP_KERNEL);
	if (!kwb_conn)
		return -ENOMEM;

	kwb_conn->wb_layer = kcrtc->master->wb_layer;

	wb_conn = &kwb_conn->base;
	wb_conn->encoder.possible_crtcs = BIT(drm_crtc_index(&kcrtc->base));

	formats = komeda_get_layer_fourcc_list(&mdev->fmt_tbl,
					       kwb_conn->wb_layer->layer_type,
					       &n_formats);

	err = drm_writeback_connector_init(&kms->base, wb_conn,
					   &komeda_wb_connector_funcs,
					   &komeda_wb_encoder_helper_funcs,
					   formats, n_formats);
	komeda_put_fourcc_list(formats);
	if (err)
		return err;

	drm_connector_helper_add(&wb_conn->base, &komeda_wb_conn_helper_funcs);

	kcrtc->wb_conn = kwb_conn;

	return 0;
}
