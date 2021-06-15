static int __ipmi_bmc_register(struct ipmi_smi *intf,
			       struct ipmi_device_id *id,
			       bool guid_set, guid_t *guid, int intf_num)
{
	int               rv;
	struct bmc_device *bmc;
	struct bmc_device *old_bmc;

	/*
	 * platform_device_register() can cause bmc_reg_mutex to
	 * be claimed because of the is_visible functions of
	 * the attributes.  Eliminate possible recursion and
	 * release the lock.
	 */
	intf->in_bmc_register = true;
	mutex_unlock(&intf->bmc_reg_mutex);

	/*
	 * Try to find if there is an bmc_device struct
	 * representing the interfaced BMC already
	 */
	mutex_lock(&ipmidriver_mutex);
	if (guid_set)
		old_bmc = ipmi_find_bmc_guid(&ipmidriver.driver, guid);
	else
		old_bmc = ipmi_find_bmc_prod_dev_id(&ipmidriver.driver,
						    id->product_id,
						    id->device_id);

	/*
	 * If there is already an bmc_device, free the new one,
	 * otherwise register the new BMC device
	 */
	if (old_bmc) {
		bmc = old_bmc;
		/*
		 * Note: old_bmc already has usecount incremented by
		 * the BMC find functions.
		 */
		intf->bmc = old_bmc;
		mutex_lock(&bmc->dyn_mutex);
		list_add_tail(&intf->bmc_link, &bmc->intfs);
		mutex_unlock(&bmc->dyn_mutex);

		dev_info(intf->si_dev,
			 "interfacing existing BMC (man_id: 0x%6.6x, prod_id: 0x%4.4x, dev_id: 0x%2.2x)\n",
			 bmc->id.manufacturer_id,
			 bmc->id.product_id,
			 bmc->id.device_id);
	} else {
		bmc = kzalloc(sizeof(*bmc), GFP_KERNEL);
		if (!bmc) {
			rv = -ENOMEM;
			goto out;
		}
		INIT_LIST_HEAD(&bmc->intfs);
		mutex_init(&bmc->dyn_mutex);
		INIT_WORK(&bmc->remove_work, cleanup_bmc_work);

		bmc->id = *id;
		bmc->dyn_id_set = 1;
		bmc->dyn_guid_set = guid_set;
		bmc->guid = *guid;
		bmc->dyn_id_expiry = jiffies + IPMI_DYN_DEV_ID_EXPIRY;

		bmc->pdev.name = "ipmi_bmc";

		rv = ida_simple_get(&ipmi_bmc_ida, 0, 0, GFP_KERNEL);
		if (rv < 0)
			goto out;
		bmc->pdev.dev.driver = &ipmidriver.driver;
		bmc->pdev.id = rv;
		bmc->pdev.dev.release = release_bmc_device;
		bmc->pdev.dev.type = &bmc_device_type;
		kref_init(&bmc->usecount);

		intf->bmc = bmc;
		mutex_lock(&bmc->dyn_mutex);
		list_add_tail(&intf->bmc_link, &bmc->intfs);
		mutex_unlock(&bmc->dyn_mutex);

		rv = platform_device_register(&bmc->pdev);
		if (rv) {
			dev_err(intf->si_dev,
				"Unable to register bmc device: %d\n",
				rv);
			goto out_list_del;
		}

		dev_info(intf->si_dev,
			 "Found new BMC (man_id: 0x%6.6x, prod_id: 0x%4.4x, dev_id: 0x%2.2x)\n",
			 bmc->id.manufacturer_id,
			 bmc->id.product_id,
			 bmc->id.device_id);
	}

	/*
	 * create symlink from system interface device to bmc device
	 * and back.
	 */
	rv = sysfs_create_link(&intf->si_dev->kobj, &bmc->pdev.dev.kobj, "bmc");
	if (rv) {
		dev_err(intf->si_dev, "Unable to create bmc symlink: %d\n", rv);
		goto out_put_bmc;
	}

	if (intf_num == -1)
		intf_num = intf->intf_num;
	intf->my_dev_name = kasprintf(GFP_KERNEL, "ipmi%d", intf_num);
	if (!intf->my_dev_name) {
		rv = -ENOMEM;
		dev_err(intf->si_dev, "Unable to allocate link from BMC: %d\n",
			rv);
		goto out_unlink1;
	}

	rv = sysfs_create_link(&bmc->pdev.dev.kobj, &intf->si_dev->kobj,
			       intf->my_dev_name);
	if (rv) {
		kfree(intf->my_dev_name);
		intf->my_dev_name = NULL;
		dev_err(intf->si_dev, "Unable to create symlink to bmc: %d\n",
			rv);
		goto out_free_my_dev_name;
	}

	intf->bmc_registered = true;

out:
	mutex_unlock(&ipmidriver_mutex);
	mutex_lock(&intf->bmc_reg_mutex);
	intf->in_bmc_register = false;
	return rv;


out_free_my_dev_name:
	kfree(intf->my_dev_name);
	intf->my_dev_name = NULL;

out_unlink1:
	sysfs_remove_link(&intf->si_dev->kobj, "bmc");

out_put_bmc:
	mutex_lock(&bmc->dyn_mutex);
	list_del(&intf->bmc_link);
	mutex_unlock(&bmc->dyn_mutex);
	intf->bmc = &intf->tmp_bmc;
	kref_put(&bmc->usecount, cleanup_bmc_device);
	goto out;

out_list_del:
	mutex_lock(&bmc->dyn_mutex);
	list_del(&intf->bmc_link);
	mutex_unlock(&bmc->dyn_mutex);
	intf->bmc = &intf->tmp_bmc;
	put_device(&bmc->pdev.dev);
	goto out;
}
