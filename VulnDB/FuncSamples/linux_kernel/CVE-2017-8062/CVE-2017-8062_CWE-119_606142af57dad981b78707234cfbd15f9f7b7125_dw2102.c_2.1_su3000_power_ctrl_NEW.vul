static int su3000_power_ctrl(struct dvb_usb_device *d, int i)
{
	struct dw2102_state *state = (struct dw2102_state *)d->priv;
	int ret = 0;

	info("%s: %d, initialized %d", __func__, i, state->initialized);

	if (i && !state->initialized) {
		mutex_lock(&d->data_mutex);

		state->data[0] = 0xde;
		state->data[1] = 0;

		state->initialized = 1;
		/* reset board */
		ret = dvb_usb_generic_rw(d, state->data, 2, NULL, 0, 0);
		mutex_unlock(&d->data_mutex);
	}

	return ret;
}
