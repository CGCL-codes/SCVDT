int rtl_usb_probe(struct usb_interface *intf,
		  const struct usb_device_id *id,
		  struct rtl_hal_cfg *rtl_hal_cfg)
{
	int err;
	struct ieee80211_hw *hw = NULL;
	struct rtl_priv *rtlpriv = NULL;
	struct usb_device	*udev;
	struct rtl_usb_priv *usb_priv;

	hw = ieee80211_alloc_hw(sizeof(struct rtl_priv) +
				sizeof(struct rtl_usb_priv), &rtl_ops);
	if (!hw) {
		WARN_ONCE(true, "rtl_usb: ieee80211 alloc failed\n");
		return -ENOMEM;
	}
	rtlpriv = hw->priv;
	rtlpriv->hw = hw;
	rtlpriv->usb_data = kcalloc(RTL_USB_MAX_RX_COUNT, sizeof(u32),
				    GFP_KERNEL);
	if (!rtlpriv->usb_data) {
		ieee80211_free_hw(hw);
		return -ENOMEM;
	}

	/* this spin lock must be initialized early */
	spin_lock_init(&rtlpriv->locks.usb_lock);
	INIT_WORK(&rtlpriv->works.fill_h2c_cmd,
		  rtl_fill_h2c_cmd_work_callback);
	INIT_WORK(&rtlpriv->works.lps_change_work,
		  rtl_lps_change_work_callback);

	rtlpriv->usb_data_index = 0;
	init_completion(&rtlpriv->firmware_loading_complete);
	SET_IEEE80211_DEV(hw, &intf->dev);
	udev = interface_to_usbdev(intf);
	usb_get_dev(udev);
	usb_priv = rtl_usbpriv(hw);
	memset(usb_priv, 0, sizeof(*usb_priv));
	usb_priv->dev.intf = intf;
	usb_priv->dev.udev = udev;
	usb_set_intfdata(intf, hw);
	/* init cfg & intf_ops */
	rtlpriv->rtlhal.interface = INTF_USB;
	rtlpriv->cfg = rtl_hal_cfg;
	rtlpriv->intf_ops = &rtl_usb_ops;
	/* Init IO handler */
	_rtl_usb_io_handler_init(&udev->dev, hw);
	rtlpriv->cfg->ops->read_chip_version(hw);
	/*like read eeprom and so on */
	rtlpriv->cfg->ops->read_eeprom_info(hw);
	err = _rtl_usb_init(hw);
	if (err)
		goto error_out2;
	rtl_usb_init_sw(hw);
	/* Init mac80211 sw */
	err = rtl_init_core(hw);
	if (err) {
		pr_err("Can't allocate sw for mac80211\n");
		goto error_out2;
	}
	if (rtlpriv->cfg->ops->init_sw_vars(hw)) {
		pr_err("Can't init_sw_vars\n");
		goto error_out;
	}
	rtlpriv->cfg->ops->init_sw_leds(hw);

	err = ieee80211_register_hw(hw);
	if (err) {
		pr_err("Can't register mac80211 hw.\n");
		err = -ENODEV;
		goto error_out;
	}
	rtlpriv->mac80211.mac80211_registered = 1;

	set_bit(RTL_STATUS_INTERFACE_START, &rtlpriv->status);
	return 0;

error_out:
	rtl_deinit_core(hw);
error_out2:
	_rtl_usb_io_handler_release(hw);
	usb_put_dev(udev);
	complete(&rtlpriv->firmware_loading_complete);
	kfree(rtlpriv->usb_data);
	return -ENODEV;
}
