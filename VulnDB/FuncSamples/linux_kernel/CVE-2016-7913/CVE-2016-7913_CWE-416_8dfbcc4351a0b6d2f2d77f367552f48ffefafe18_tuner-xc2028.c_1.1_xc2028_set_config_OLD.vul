static int xc2028_set_config(struct dvb_frontend *fe, void *priv_cfg)
{
	struct xc2028_data *priv = fe->tuner_priv;
	struct xc2028_ctrl *p    = priv_cfg;
	int                 rc   = 0;

	tuner_dbg("%s called\n", __func__);

	mutex_lock(&priv->lock);

	/*
	 * Copy the config data.
	 * For the firmware name, keep a local copy of the string,
	 * in order to avoid troubles during device release.
	 */
	kfree(priv->ctrl.fname);
	memcpy(&priv->ctrl, p, sizeof(priv->ctrl));
	if (p->fname) {
		priv->ctrl.fname = kstrdup(p->fname, GFP_KERNEL);
		if (priv->ctrl.fname == NULL)
			rc = -ENOMEM;
	}

	/*
	 * If firmware name changed, frees firmware. As free_firmware will
	 * reset the status to NO_FIRMWARE, this forces a new request_firmware
	 */
	if (!firmware_name[0] && p->fname &&
	    priv->fname && strcmp(p->fname, priv->fname))
		free_firmware(priv);

	if (priv->ctrl.max_len < 9)
		priv->ctrl.max_len = 13;

	if (priv->state == XC2028_NO_FIRMWARE) {
		if (!firmware_name[0])
			priv->fname = priv->ctrl.fname;
		else
			priv->fname = firmware_name;

		rc = request_firmware_nowait(THIS_MODULE, 1,
					     priv->fname,
					     priv->i2c_props.adap->dev.parent,
					     GFP_KERNEL,
					     fe, load_firmware_cb);
		if (rc < 0) {
			tuner_err("Failed to request firmware %s\n",
				  priv->fname);
			priv->state = XC2028_NODEV;
		} else
			priv->state = XC2028_WAITING_FIRMWARE;
	}
	mutex_unlock(&priv->lock);

	return rc;
}
