void sas_destruct_devices(struct asd_sas_port *port)
{
	struct domain_device *dev, *n;

	list_for_each_entry_safe(dev, n, &port->destroy_list, disco_list_node) {
		list_del_init(&dev->disco_list_node);

		sas_remove_children(&dev->rphy->dev);
		sas_rphy_delete(dev->rphy);
		sas_unregister_common_dev(port, dev);
	}
}
