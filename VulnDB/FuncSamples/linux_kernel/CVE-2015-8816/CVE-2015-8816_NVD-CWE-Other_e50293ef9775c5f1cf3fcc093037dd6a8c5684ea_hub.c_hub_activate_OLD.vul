static void hub_activate(struct usb_hub *hub, enum hub_activation_type type)
{
	struct usb_device *hdev = hub->hdev;
	struct usb_hcd *hcd;
	int ret;
	int port1;
	int status;
	bool need_debounce_delay = false;
	unsigned delay;

	/* Continue a partial initialization */
	if (type == HUB_INIT2)
		goto init2;
	if (type == HUB_INIT3)
		goto init3;

	/* The superspeed hub except for root hub has to use Hub Depth
	 * value as an offset into the route string to locate the bits
	 * it uses to determine the downstream port number. So hub driver
	 * should send a set hub depth request to superspeed hub after
	 * the superspeed hub is set configuration in initialization or
	 * reset procedure.
	 *
	 * After a resume, port power should still be on.
	 * For any other type of activation, turn it on.
	 */
	if (type != HUB_RESUME) {
		if (hdev->parent && hub_is_superspeed(hdev)) {
			ret = usb_control_msg(hdev, usb_sndctrlpipe(hdev, 0),
					HUB_SET_DEPTH, USB_RT_HUB,
					hdev->level - 1, 0, NULL, 0,
					USB_CTRL_SET_TIMEOUT);
			if (ret < 0)
				dev_err(hub->intfdev,
						"set hub depth failed\n");
		}

		/* Speed up system boot by using a delayed_work for the
		 * hub's initial power-up delays.  This is pretty awkward
		 * and the implementation looks like a home-brewed sort of
		 * setjmp/longjmp, but it saves at least 100 ms for each
		 * root hub (assuming usbcore is compiled into the kernel
		 * rather than as a module).  It adds up.
		 *
		 * This can't be done for HUB_RESUME or HUB_RESET_RESUME
		 * because for those activation types the ports have to be
		 * operational when we return.  In theory this could be done
		 * for HUB_POST_RESET, but it's easier not to.
		 */
		if (type == HUB_INIT) {
			delay = hub_power_on_good_delay(hub);

			hub_power_on(hub, false);
			INIT_DELAYED_WORK(&hub->init_work, hub_init_func2);
			queue_delayed_work(system_power_efficient_wq,
					&hub->init_work,
					msecs_to_jiffies(delay));

			/* Suppress autosuspend until init is done */
			usb_autopm_get_interface_no_resume(
					to_usb_interface(hub->intfdev));
			return;		/* Continues at init2: below */
		} else if (type == HUB_RESET_RESUME) {
			/* The internal host controller state for the hub device
			 * may be gone after a host power loss on system resume.
			 * Update the device's info so the HW knows it's a hub.
			 */
			hcd = bus_to_hcd(hdev->bus);
			if (hcd->driver->update_hub_device) {
				ret = hcd->driver->update_hub_device(hcd, hdev,
						&hub->tt, GFP_NOIO);
				if (ret < 0) {
					dev_err(hub->intfdev, "Host not "
							"accepting hub info "
							"update.\n");
					dev_err(hub->intfdev, "LS/FS devices "
							"and hubs may not work "
							"under this hub\n.");
				}
			}
			hub_power_on(hub, true);
		} else {
			hub_power_on(hub, true);
		}
	}
 init2:

	/*
	 * Check each port and set hub->change_bits to let hub_wq know
	 * which ports need attention.
	 */
	for (port1 = 1; port1 <= hdev->maxchild; ++port1) {
		struct usb_port *port_dev = hub->ports[port1 - 1];
		struct usb_device *udev = port_dev->child;
		u16 portstatus, portchange;

		portstatus = portchange = 0;
		status = hub_port_status(hub, port1, &portstatus, &portchange);
		if (udev || (portstatus & USB_PORT_STAT_CONNECTION))
			dev_dbg(&port_dev->dev, "status %04x change %04x\n",
					portstatus, portchange);

		/*
		 * After anything other than HUB_RESUME (i.e., initialization
		 * or any sort of reset), every port should be disabled.
		 * Unconnected ports should likewise be disabled (paranoia),
		 * and so should ports for which we have no usb_device.
		 */
		if ((portstatus & USB_PORT_STAT_ENABLE) && (
				type != HUB_RESUME ||
				!(portstatus & USB_PORT_STAT_CONNECTION) ||
				!udev ||
				udev->state == USB_STATE_NOTATTACHED)) {
			/*
			 * USB3 protocol ports will automatically transition
			 * to Enabled state when detect an USB3.0 device attach.
			 * Do not disable USB3 protocol ports, just pretend
			 * power was lost
			 */
			portstatus &= ~USB_PORT_STAT_ENABLE;
			if (!hub_is_superspeed(hdev))
				usb_clear_port_feature(hdev, port1,
						   USB_PORT_FEAT_ENABLE);
		}

		/* Clear status-change flags; we'll debounce later */
		if (portchange & USB_PORT_STAT_C_CONNECTION) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_CONNECTION);
		}
		if (portchange & USB_PORT_STAT_C_ENABLE) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_ENABLE);
		}
		if (portchange & USB_PORT_STAT_C_RESET) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_RESET);
		}
		if ((portchange & USB_PORT_STAT_C_BH_RESET) &&
				hub_is_superspeed(hub->hdev)) {
			need_debounce_delay = true;
			usb_clear_port_feature(hub->hdev, port1,
					USB_PORT_FEAT_C_BH_PORT_RESET);
		}
		/* We can forget about a "removed" device when there's a
		 * physical disconnect or the connect status changes.
		 */
		if (!(portstatus & USB_PORT_STAT_CONNECTION) ||
				(portchange & USB_PORT_STAT_C_CONNECTION))
			clear_bit(port1, hub->removed_bits);

		if (!udev || udev->state == USB_STATE_NOTATTACHED) {
			/* Tell hub_wq to disconnect the device or
			 * check for a new connection
			 */
			if (udev || (portstatus & USB_PORT_STAT_CONNECTION) ||
			    (portstatus & USB_PORT_STAT_OVERCURRENT))
				set_bit(port1, hub->change_bits);

		} else if (portstatus & USB_PORT_STAT_ENABLE) {
			bool port_resumed = (portstatus &
					USB_PORT_STAT_LINK_STATE) ==
				USB_SS_PORT_LS_U0;
			/* The power session apparently survived the resume.
			 * If there was an overcurrent or suspend change
			 * (i.e., remote wakeup request), have hub_wq
			 * take care of it.  Look at the port link state
			 * for USB 3.0 hubs, since they don't have a suspend
			 * change bit, and they don't set the port link change
			 * bit on device-initiated resume.
			 */
			if (portchange || (hub_is_superspeed(hub->hdev) &&
						port_resumed))
				set_bit(port1, hub->change_bits);

		} else if (udev->persist_enabled) {
#ifdef CONFIG_PM
			udev->reset_resume = 1;
#endif
			/* Don't set the change_bits when the device
			 * was powered off.
			 */
			if (test_bit(port1, hub->power_bits))
				set_bit(port1, hub->change_bits);

		} else {
			/* The power session is gone; tell hub_wq */
			usb_set_device_state(udev, USB_STATE_NOTATTACHED);
			set_bit(port1, hub->change_bits);
		}
	}

	/* If no port-status-change flags were set, we don't need any
	 * debouncing.  If flags were set we can try to debounce the
	 * ports all at once right now, instead of letting hub_wq do them
	 * one at a time later on.
	 *
	 * If any port-status changes do occur during this delay, hub_wq
	 * will see them later and handle them normally.
	 */
	if (need_debounce_delay) {
		delay = HUB_DEBOUNCE_STABLE;

		/* Don't do a long sleep inside a workqueue routine */
		if (type == HUB_INIT2) {
			INIT_DELAYED_WORK(&hub->init_work, hub_init_func3);
			queue_delayed_work(system_power_efficient_wq,
					&hub->init_work,
					msecs_to_jiffies(delay));
			return;		/* Continues at init3: below */
		} else {
			msleep(delay);
		}
	}
 init3:
	hub->quiescing = 0;

	status = usb_submit_urb(hub->urb, GFP_NOIO);
	if (status < 0)
		dev_err(hub->intfdev, "activate --> %d\n", status);
	if (hub->has_indicators && blinkenlights)
		queue_delayed_work(system_power_efficient_wq,
				&hub->leds, LED_CYCLE_PERIOD);

	/* Scan all ports that need attention */
	kick_hub_wq(hub);

	/* Allow autosuspend if it was suppressed */
	if (type <= HUB_INIT3)
		usb_autopm_put_interface_async(to_usb_interface(hub->intfdev));
}
