static int set_registers(rtl8150_t * dev, u16 indx, u16 size, void *data)
{
	return usb_control_msg(dev->udev, usb_sndctrlpipe(dev->udev, 0),
			       RTL8150_REQ_SET_REGS, RTL8150_REQT_WRITE,
			       indx, 0, data, size, 500);
}
