static int treo_attach(struct usb_serial *serial)
{
	struct usb_serial_port *swap_port;

	/* Only do this endpoint hack for the Handspring devices with
	 * interrupt in endpoints, which for now are the Treo devices. */
	if (!((le16_to_cpu(serial->dev->descriptor.idVendor)
						== HANDSPRING_VENDOR_ID) ||
		(le16_to_cpu(serial->dev->descriptor.idVendor)
						== KYOCERA_VENDOR_ID)) ||
		(serial->num_interrupt_in == 0))
		return 0;

	/*
	* It appears that Treos and Kyoceras want to use the
	* 1st bulk in endpoint to communicate with the 2nd bulk out endpoint,
	* so let's swap the 1st and 2nd bulk in and interrupt endpoints.
	* Note that swapping the bulk out endpoints would break lots of
	* apps that want to communicate on the second port.
	*/
#define COPY_PORT(dest, src)						\
	do { \
		int i;							\
									\
		for (i = 0; i < ARRAY_SIZE(src->read_urbs); ++i) {	\
			dest->read_urbs[i] = src->read_urbs[i];		\
			dest->read_urbs[i]->context = dest;		\
			dest->bulk_in_buffers[i] = src->bulk_in_buffers[i]; \
		}							\
		dest->read_urb = src->read_urb;				\
		dest->bulk_in_endpointAddress = src->bulk_in_endpointAddress;\
		dest->bulk_in_buffer = src->bulk_in_buffer;		\
		dest->bulk_in_size = src->bulk_in_size;			\
		dest->interrupt_in_urb = src->interrupt_in_urb;		\
		dest->interrupt_in_urb->context = dest;			\
		dest->interrupt_in_endpointAddress = \
					src->interrupt_in_endpointAddress;\
		dest->interrupt_in_buffer = src->interrupt_in_buffer;	\
	} while (0);

	swap_port = kmalloc(sizeof(*swap_port), GFP_KERNEL);
	if (!swap_port)
		return -ENOMEM;
	COPY_PORT(swap_port, serial->port[0]);
	COPY_PORT(serial->port[0], serial->port[1]);
	COPY_PORT(serial->port[1], swap_port);
	kfree(swap_port);

	return 0;
}
