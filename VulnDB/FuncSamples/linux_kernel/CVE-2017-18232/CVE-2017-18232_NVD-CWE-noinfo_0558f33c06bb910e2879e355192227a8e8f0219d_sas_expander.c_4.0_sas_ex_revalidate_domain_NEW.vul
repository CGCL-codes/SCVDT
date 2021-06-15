int sas_ex_revalidate_domain(struct domain_device *port_dev)
{
	int res;
	struct domain_device *dev = NULL;

	res = sas_find_bcast_dev(port_dev, &dev);
	if (res == 0 && dev) {
		struct expander_device *ex = &dev->ex_dev;
		int i = 0, phy_id;

		do {
			phy_id = -1;
			res = sas_find_bcast_phy(dev, &phy_id, i, true);
			if (phy_id == -1)
				break;
			res = sas_rediscover(dev, phy_id);
			i = phy_id + 1;
		} while (i < ex->num_phys);
	}
	return res;
}
