static int hci_uart_set_proto(struct hci_uart *hu, int id)
{
	const struct hci_uart_proto *p;
	int err;

	p = hci_uart_get_proto(id);
	if (!p)
		return -EPROTONOSUPPORT;

	hu->proto = p;

	err = hci_uart_register_dev(hu);
	if (err) {
		return err;
	}

	set_bit(HCI_UART_PROTO_READY, &hu->flags);
	return 0;
}
