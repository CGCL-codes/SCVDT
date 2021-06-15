static int hidp_setup_hid(struct hidp_session *session,
				struct hidp_connadd_req *req)
{
	struct hid_device *hid;
	int err;

	session->rd_data = kzalloc(req->rd_size, GFP_KERNEL);
	if (!session->rd_data)
		return -ENOMEM;

	if (copy_from_user(session->rd_data, req->rd_data, req->rd_size)) {
		err = -EFAULT;
		goto fault;
	}
	session->rd_size = req->rd_size;

	hid = hid_allocate_device();
	if (IS_ERR(hid)) {
		err = PTR_ERR(hid);
		goto fault;
	}

	session->hid = hid;

	hid->driver_data = session;

	hid->bus     = BUS_BLUETOOTH;
	hid->vendor  = req->vendor;
	hid->product = req->product;
	hid->version = req->version;
	hid->country = req->country;

	strncpy(hid->name, req->name, 128);

	snprintf(hid->phys, sizeof(hid->phys), "%pMR",
		 &bt_sk(session->ctrl_sock->sk)->src);

	snprintf(hid->uniq, sizeof(hid->uniq), "%pMR",
		 &bt_sk(session->ctrl_sock->sk)->dst);

	hid->dev.parent = &session->conn->dev;
	hid->ll_driver = &hidp_hid_driver;

	hid->hid_get_raw_report = hidp_get_raw_report;
	hid->hid_output_raw_report = hidp_output_raw_report;

	/* True if device is blacklisted in drivers/hid/hid-core.c */
	if (hid_ignore(hid)) {
		hid_destroy_device(session->hid);
		session->hid = NULL;
		return -ENODEV;
	}

	return 0;

fault:
	kfree(session->rd_data);
	session->rd_data = NULL;

	return err;
}
