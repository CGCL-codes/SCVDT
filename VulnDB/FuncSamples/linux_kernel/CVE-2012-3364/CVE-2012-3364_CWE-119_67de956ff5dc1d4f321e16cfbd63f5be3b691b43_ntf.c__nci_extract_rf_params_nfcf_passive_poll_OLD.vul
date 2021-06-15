static __u8 *nci_extract_rf_params_nfcf_passive_poll(struct nci_dev *ndev,
			struct rf_tech_specific_params_nfcf_poll *nfcf_poll,
						     __u8 *data)
{
	nfcf_poll->bit_rate = *data++;
	nfcf_poll->sensf_res_len = *data++;

	pr_debug("bit_rate %d, sensf_res_len %d\n",
		 nfcf_poll->bit_rate, nfcf_poll->sensf_res_len);

	memcpy(nfcf_poll->sensf_res, data, nfcf_poll->sensf_res_len);
	data += nfcf_poll->sensf_res_len;

	return data;
}
