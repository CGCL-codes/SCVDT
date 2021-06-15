static void sas_unregister_devs_sas_addr(struct domain_device *parent,
					 int phy_id, bool last)
{
	struct expander_device *ex_dev = &parent->ex_dev;
	struct ex_phy *phy = &ex_dev->ex_phy[phy_id];
	struct domain_device *child, *n, *found = NULL;
	if (last) {
		list_for_each_entry_safe(child, n,
			&ex_dev->children, siblings) {
			if (SAS_ADDR(child->sas_addr) ==
			    SAS_ADDR(phy->attached_sas_addr)) {
				set_bit(SAS_DEV_GONE, &child->state);
				if (child->dev_type == SAS_EDGE_EXPANDER_DEVICE ||
				    child->dev_type == SAS_FANOUT_EXPANDER_DEVICE)
					sas_unregister_ex_tree(parent->port, child);
				else
					sas_unregister_dev(parent->port, child);
				found = child;
				break;
			}
		}
		sas_disable_routing(parent, phy->attached_sas_addr);
	}
	memset(phy->attached_sas_addr, 0, SAS_ADDR_SIZE);
	if (phy->port) {
		sas_port_delete_phy(phy->port, phy->phy);
		sas_device_set_phy(found, phy->port);
		if (phy->port->num_phys == 0)
			list_add_tail(&phy->port->del_list,
				&parent->port->sas_port_del_list);
		phy->port = NULL;
	}
}
