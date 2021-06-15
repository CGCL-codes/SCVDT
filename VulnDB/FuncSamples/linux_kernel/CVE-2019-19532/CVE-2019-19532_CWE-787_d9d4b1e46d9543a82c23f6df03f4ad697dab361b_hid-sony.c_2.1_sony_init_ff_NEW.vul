static int sony_init_ff(struct sony_sc *sc)
{
	struct hid_input *hidinput;
	struct input_dev *input_dev;

	if (list_empty(&sc->hdev->inputs)) {
		hid_err(sc->hdev, "no inputs found\n");
		return -ENODEV;
	}
	hidinput = list_entry(sc->hdev->inputs.next, struct hid_input, list);
	input_dev = hidinput->input;

	input_set_capability(input_dev, EV_FF, FF_RUMBLE);
	return input_ff_create_memless(input_dev, NULL, sony_play_effect);
}
