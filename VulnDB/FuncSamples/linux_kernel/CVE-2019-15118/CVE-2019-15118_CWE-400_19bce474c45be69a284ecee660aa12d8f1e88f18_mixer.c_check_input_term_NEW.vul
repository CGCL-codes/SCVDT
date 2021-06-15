static int check_input_term(struct mixer_build *state, int id,
			    struct usb_audio_term *term)
{
	memset(term, 0, sizeof(*term));
	memset(state->termbitmap, 0, sizeof(state->termbitmap));
	return __check_input_term(state, id, term);
}
