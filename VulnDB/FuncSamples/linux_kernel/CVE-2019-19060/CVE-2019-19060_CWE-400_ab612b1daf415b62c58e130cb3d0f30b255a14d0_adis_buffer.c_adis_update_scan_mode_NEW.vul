int adis_update_scan_mode(struct iio_dev *indio_dev,
	const unsigned long *scan_mask)
{
	struct adis *adis = iio_device_get_drvdata(indio_dev);
	const struct iio_chan_spec *chan;
	unsigned int scan_count;
	unsigned int i, j;
	__be16 *tx, *rx;

	kfree(adis->xfer);
	kfree(adis->buffer);

	if (adis->burst && adis->burst->en)
		return adis_update_scan_mode_burst(indio_dev, scan_mask);

	scan_count = indio_dev->scan_bytes / 2;

	adis->xfer = kcalloc(scan_count + 1, sizeof(*adis->xfer), GFP_KERNEL);
	if (!adis->xfer)
		return -ENOMEM;

	adis->buffer = kcalloc(indio_dev->scan_bytes, 2, GFP_KERNEL);
	if (!adis->buffer) {
		kfree(adis->xfer);
		adis->xfer = NULL;
		return -ENOMEM;
	}

	rx = adis->buffer;
	tx = rx + scan_count;

	spi_message_init(&adis->msg);

	for (j = 0; j <= scan_count; j++) {
		adis->xfer[j].bits_per_word = 8;
		if (j != scan_count)
			adis->xfer[j].cs_change = 1;
		adis->xfer[j].len = 2;
		adis->xfer[j].delay_usecs = adis->data->read_delay;
		if (j < scan_count)
			adis->xfer[j].tx_buf = &tx[j];
		if (j >= 1)
			adis->xfer[j].rx_buf = &rx[j - 1];
		spi_message_add_tail(&adis->xfer[j], &adis->msg);
	}

	chan = indio_dev->channels;
	for (i = 0; i < indio_dev->num_channels; i++, chan++) {
		if (!test_bit(chan->scan_index, scan_mask))
			continue;
		if (chan->scan_type.storagebits == 32)
			*tx++ = cpu_to_be16((chan->address + 2) << 8);
		*tx++ = cpu_to_be16(chan->address << 8);
	}

	return 0;
}
