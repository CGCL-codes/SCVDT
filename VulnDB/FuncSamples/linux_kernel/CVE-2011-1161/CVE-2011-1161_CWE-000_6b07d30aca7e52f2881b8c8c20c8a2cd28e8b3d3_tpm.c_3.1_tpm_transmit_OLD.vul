static ssize_t tpm_transmit(struct tpm_chip *chip, const char *buf,
			    size_t bufsiz)
{
	ssize_t rc;
	u32 count, ordinal;
	unsigned long stop;

	count = be32_to_cpu(*((__be32 *) (buf + 2)));
	ordinal = be32_to_cpu(*((__be32 *) (buf + 6)));
	if (count == 0)
		return -ENODATA;
	if (count > bufsiz) {
		dev_err(chip->dev,
			"invalid count value %x %zx \n", count, bufsiz);
		return -E2BIG;
	}

	mutex_lock(&chip->tpm_mutex);

	if ((rc = chip->vendor.send(chip, (u8 *) buf, count)) < 0) {
		dev_err(chip->dev,
			"tpm_transmit: tpm_send: error %zd\n", rc);
		goto out;
	}

	if (chip->vendor.irq)
		goto out_recv;

	stop = jiffies + tpm_calc_ordinal_duration(chip, ordinal);
	do {
		u8 status = chip->vendor.status(chip);
		if ((status & chip->vendor.req_complete_mask) ==
		    chip->vendor.req_complete_val)
			goto out_recv;

		if ((status == chip->vendor.req_canceled)) {
			dev_err(chip->dev, "Operation Canceled\n");
			rc = -ECANCELED;
			goto out;
		}

		msleep(TPM_TIMEOUT);	/* CHECK */
		rmb();
	} while (time_before(jiffies, stop));

	chip->vendor.cancel(chip);
	dev_err(chip->dev, "Operation Timed out\n");
	rc = -ETIME;
	goto out;

out_recv:
	rc = chip->vendor.recv(chip, (u8 *) buf, bufsiz);
	if (rc < 0)
		dev_err(chip->dev,
			"tpm_transmit: tpm_recv: error %zd\n", rc);
out:
	mutex_unlock(&chip->tpm_mutex);
	return rc;
}
