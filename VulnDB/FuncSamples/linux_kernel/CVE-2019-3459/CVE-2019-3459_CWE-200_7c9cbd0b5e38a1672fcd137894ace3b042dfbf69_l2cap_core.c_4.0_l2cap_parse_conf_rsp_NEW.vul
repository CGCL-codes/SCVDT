static int l2cap_parse_conf_rsp(struct l2cap_chan *chan, void *rsp, int len,
				void *data, size_t size, u16 *result)
{
	struct l2cap_conf_req *req = data;
	void *ptr = req->data;
	void *endptr = data + size;
	int type, olen;
	unsigned long val;
	struct l2cap_conf_rfc rfc = { .mode = L2CAP_MODE_BASIC };
	struct l2cap_conf_efs efs;

	BT_DBG("chan %p, rsp %p, len %d, req %p", chan, rsp, len, data);

	while (len >= L2CAP_CONF_OPT_SIZE) {
		len -= l2cap_get_conf_opt(&rsp, &type, &olen, &val);
		if (len < 0)
			break;

		switch (type) {
		case L2CAP_CONF_MTU:
			if (olen != 2)
				break;
			if (val < L2CAP_DEFAULT_MIN_MTU) {
				*result = L2CAP_CONF_UNACCEPT;
				chan->imtu = L2CAP_DEFAULT_MIN_MTU;
			} else
				chan->imtu = val;
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_MTU, 2, chan->imtu,
					   endptr - ptr);
			break;

		case L2CAP_CONF_FLUSH_TO:
			if (olen != 2)
				break;
			chan->flush_to = val;
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_FLUSH_TO, 2,
					   chan->flush_to, endptr - ptr);
			break;

		case L2CAP_CONF_RFC:
			if (olen != sizeof(rfc))
				break;
			memcpy(&rfc, (void *)val, olen);
			if (test_bit(CONF_STATE2_DEVICE, &chan->conf_state) &&
			    rfc.mode != chan->mode)
				return -ECONNREFUSED;
			chan->fcs = 0;
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc),
					   (unsigned long) &rfc, endptr - ptr);
			break;

		case L2CAP_CONF_EWS:
			if (olen != 2)
				break;
			chan->ack_win = min_t(u16, val, chan->ack_win);
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_EWS, 2,
					   chan->tx_win, endptr - ptr);
			break;

		case L2CAP_CONF_EFS:
			if (olen != sizeof(efs))
				break;
			memcpy(&efs, (void *)val, olen);
			if (chan->local_stype != L2CAP_SERV_NOTRAFIC &&
			    efs.stype != L2CAP_SERV_NOTRAFIC &&
			    efs.stype != chan->local_stype)
				return -ECONNREFUSED;
			l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS, sizeof(efs),
					   (unsigned long) &efs, endptr - ptr);
			break;

		case L2CAP_CONF_FCS:
			if (olen != 1)
				break;
			if (*result == L2CAP_CONF_PENDING)
				if (val == L2CAP_FCS_NONE)
					set_bit(CONF_RECV_NO_FCS,
						&chan->conf_state);
			break;
		}
	}

	if (chan->mode == L2CAP_MODE_BASIC && chan->mode != rfc.mode)
		return -ECONNREFUSED;

	chan->mode = rfc.mode;

	if (*result == L2CAP_CONF_SUCCESS || *result == L2CAP_CONF_PENDING) {
		switch (rfc.mode) {
		case L2CAP_MODE_ERTM:
			chan->retrans_timeout = le16_to_cpu(rfc.retrans_timeout);
			chan->monitor_timeout = le16_to_cpu(rfc.monitor_timeout);
			chan->mps    = le16_to_cpu(rfc.max_pdu_size);
			if (!test_bit(FLAG_EXT_CTRL, &chan->flags))
				chan->ack_win = min_t(u16, chan->ack_win,
						      rfc.txwin_size);

			if (test_bit(FLAG_EFS_ENABLE, &chan->flags)) {
				chan->local_msdu = le16_to_cpu(efs.msdu);
				chan->local_sdu_itime =
					le32_to_cpu(efs.sdu_itime);
				chan->local_acc_lat = le32_to_cpu(efs.acc_lat);
				chan->local_flush_to =
					le32_to_cpu(efs.flush_to);
			}
			break;

		case L2CAP_MODE_STREAMING:
			chan->mps    = le16_to_cpu(rfc.max_pdu_size);
		}
	}

	req->dcid   = cpu_to_le16(chan->dcid);
	req->flags  = cpu_to_le16(0);

	return ptr - data;
}
