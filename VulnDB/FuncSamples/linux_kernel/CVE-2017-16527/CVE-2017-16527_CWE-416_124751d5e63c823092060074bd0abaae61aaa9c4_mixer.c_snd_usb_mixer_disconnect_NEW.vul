void snd_usb_mixer_disconnect(struct usb_mixer_interface *mixer)
{
	if (mixer->disconnected)
		return;
	if (mixer->urb)
		usb_kill_urb(mixer->urb);
	if (mixer->rc_urb)
		usb_kill_urb(mixer->rc_urb);
	mixer->disconnected = true;
}
