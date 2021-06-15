int snd_usb_pipe_sanity_check(struct usb_device *dev, unsigned int pipe)
{
	static const int pipetypes[4] = {
		PIPE_CONTROL, PIPE_ISOCHRONOUS, PIPE_BULK, PIPE_INTERRUPT
	};
	struct usb_host_endpoint *ep;

	ep = usb_pipe_endpoint(dev, pipe);
	if (!ep || usb_pipetype(pipe) != pipetypes[usb_endpoint_type(&ep->desc)])
		return -EINVAL;
	return 0;
}
