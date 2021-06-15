static int usb_audio_probe(struct usb_interface *intf,
			   const struct usb_device_id *usb_id)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	const struct snd_usb_audio_quirk *quirk =
		(const struct snd_usb_audio_quirk *)usb_id->driver_info;
	struct snd_usb_audio *chip;
	int i, err;
	struct usb_host_interface *alts;
	int ifnum;
	u32 id;

	alts = &intf->altsetting[0];
	ifnum = get_iface_desc(alts)->bInterfaceNumber;
	id = USB_ID(le16_to_cpu(dev->descriptor.idVendor),
		    le16_to_cpu(dev->descriptor.idProduct));
	if (get_alias_id(dev, &id))
		quirk = get_alias_quirk(dev, id);
	if (quirk && quirk->ifnum >= 0 && ifnum != quirk->ifnum)
		return -ENXIO;

	err = snd_usb_apply_boot_quirk(dev, intf, quirk, id);
	if (err < 0)
		return err;

	/*
	 * found a config.  now register to ALSA
	 */

	/* check whether it's already registered */
	chip = NULL;
	mutex_lock(&register_mutex);
	for (i = 0; i < SNDRV_CARDS; i++) {
		if (usb_chip[i] && usb_chip[i]->dev == dev) {
			if (atomic_read(&usb_chip[i]->shutdown)) {
				dev_err(&dev->dev, "USB device is in the shutdown state, cannot create a card instance\n");
				err = -EIO;
				goto __error;
			}
			chip = usb_chip[i];
			atomic_inc(&chip->active); /* avoid autopm */
			break;
		}
	}
	if (! chip) {
		/* it's a fresh one.
		 * now look for an empty slot and create a new card instance
		 */
		for (i = 0; i < SNDRV_CARDS; i++)
			if (!usb_chip[i] &&
			    (vid[i] == -1 || vid[i] == USB_ID_VENDOR(id)) &&
			    (pid[i] == -1 || pid[i] == USB_ID_PRODUCT(id))) {
				if (enable[i]) {
					err = snd_usb_audio_create(intf, dev, i, quirk,
								   id, &chip);
					if (err < 0)
						goto __error;
					chip->pm_intf = intf;
					break;
				} else if (vid[i] != -1 || pid[i] != -1) {
					dev_info(&dev->dev,
						 "device (%04x:%04x) is disabled\n",
						 USB_ID_VENDOR(id),
						 USB_ID_PRODUCT(id));
					err = -ENOENT;
					goto __error;
				}
			}
		if (!chip) {
			dev_err(&dev->dev, "no available usb audio device\n");
			err = -ENODEV;
			goto __error;
		}
	}
	dev_set_drvdata(&dev->dev, chip);

	/*
	 * For devices with more than one control interface, we assume the
	 * first contains the audio controls. We might need a more specific
	 * check here in the future.
	 */
	if (!chip->ctrl_intf)
		chip->ctrl_intf = alts;

	chip->txfr_quirk = 0;
	err = 1; /* continue */
	if (quirk && quirk->ifnum != QUIRK_NO_INTERFACE) {
		/* need some special handlings */
		err = snd_usb_create_quirk(chip, intf, &usb_audio_driver, quirk);
		if (err < 0)
			goto __error;
	}

	if (err > 0) {
		/* create normal USB audio interfaces */
		err = snd_usb_create_streams(chip, ifnum);
		if (err < 0)
			goto __error;
		err = snd_usb_create_mixer(chip, ifnum, ignore_ctl_error);
		if (err < 0)
			goto __error;
	}

	/* we are allowed to call snd_card_register() many times */
	err = snd_card_register(chip->card);
	if (err < 0)
		goto __error;

	usb_chip[chip->index] = chip;
	chip->num_interfaces++;
	usb_set_intfdata(intf, chip);
	atomic_dec(&chip->active);
	mutex_unlock(&register_mutex);
	return 0;

 __error:
	if (chip) {
		/* chip->active is inside the chip->card object,
		 * decrement before memory is possibly returned.
		 */
		atomic_dec(&chip->active);
		if (!chip->num_interfaces)
			snd_card_free(chip->card);
	}
	mutex_unlock(&register_mutex);
	return err;
}
