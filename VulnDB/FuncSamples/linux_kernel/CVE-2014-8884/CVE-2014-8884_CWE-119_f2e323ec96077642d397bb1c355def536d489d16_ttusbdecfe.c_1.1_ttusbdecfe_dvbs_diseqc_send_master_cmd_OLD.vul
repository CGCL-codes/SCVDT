static int ttusbdecfe_dvbs_diseqc_send_master_cmd(struct dvb_frontend* fe, struct dvb_diseqc_master_cmd *cmd)
{
	struct ttusbdecfe_state* state = (struct ttusbdecfe_state*) fe->demodulator_priv;
	u8 b[] = { 0x00, 0xff, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00 };

	memcpy(&b[4], cmd->msg, cmd->msg_len);

	state->config->send_command(fe, 0x72,
				    sizeof(b) - (6 - cmd->msg_len), b,
				    NULL, NULL);

	return 0;
}
