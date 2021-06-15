static int intel_open(struct hci_uart *hu)
{
	struct intel_data *intel;

	BT_DBG("hu %p", hu);

	intel = kzalloc(sizeof(*intel), GFP_KERNEL);
	if (!intel)
		return -ENOMEM;

	skb_queue_head_init(&intel->txq);
	INIT_WORK(&intel->busy_work, intel_busy_work);

	intel->hu = hu;

	hu->priv = intel;

	if (!intel_set_power(hu, true))
		set_bit(STATE_BOOTING, &intel->flags);

	return 0;
}
