static int su3000_power_ctrl(struct dvb_usb_device *d, int i)
{
	struct dw2102_state *state = (struct dw2102_state *)d->priv;
	u8 obuf[] = {0xde, 0};

	info("%s: %d, initialized %d", __func__, i, state->initialized);

	if (i && !state->initialized) {
		state->initialized = 1;
		/* reset board */
		return dvb_usb_generic_rw(d, obuf, 2, NULL, 0, 0);
	}

	return 0;
}
