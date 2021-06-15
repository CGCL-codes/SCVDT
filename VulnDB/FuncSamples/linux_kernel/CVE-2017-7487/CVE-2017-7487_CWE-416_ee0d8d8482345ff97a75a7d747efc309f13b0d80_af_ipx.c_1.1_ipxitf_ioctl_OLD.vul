static int ipxitf_ioctl(unsigned int cmd, void __user *arg)
{
	int rc = -EINVAL;
	struct ifreq ifr;
	int val;

	switch (cmd) {
	case SIOCSIFADDR: {
		struct sockaddr_ipx *sipx;
		struct ipx_interface_definition f;

		rc = -EFAULT;
		if (copy_from_user(&ifr, arg, sizeof(ifr)))
			break;
		sipx = (struct sockaddr_ipx *)&ifr.ifr_addr;
		rc = -EINVAL;
		if (sipx->sipx_family != AF_IPX)
			break;
		f.ipx_network = sipx->sipx_network;
		memcpy(f.ipx_device, ifr.ifr_name,
			sizeof(f.ipx_device));
		memcpy(f.ipx_node, sipx->sipx_node, IPX_NODE_LEN);
		f.ipx_dlink_type = sipx->sipx_type;
		f.ipx_special = sipx->sipx_special;

		if (sipx->sipx_action == IPX_DLTITF)
			rc = ipxitf_delete(&f);
		else
			rc = ipxitf_create(&f);
		break;
	}
	case SIOCGIFADDR: {
		struct sockaddr_ipx *sipx;
		struct ipx_interface *ipxif;
		struct net_device *dev;

		rc = -EFAULT;
		if (copy_from_user(&ifr, arg, sizeof(ifr)))
			break;
		sipx = (struct sockaddr_ipx *)&ifr.ifr_addr;
		dev  = __dev_get_by_name(&init_net, ifr.ifr_name);
		rc   = -ENODEV;
		if (!dev)
			break;
		ipxif = ipxitf_find_using_phys(dev,
					   ipx_map_frame_type(sipx->sipx_type));
		rc = -EADDRNOTAVAIL;
		if (!ipxif)
			break;

		sipx->sipx_family	= AF_IPX;
		sipx->sipx_network	= ipxif->if_netnum;
		memcpy(sipx->sipx_node, ipxif->if_node,
			sizeof(sipx->sipx_node));
		rc = -EFAULT;
		if (copy_to_user(arg, &ifr, sizeof(ifr)))
			break;
		ipxitf_put(ipxif);
		rc = 0;
		break;
	}
	case SIOCAIPXITFCRT:
		rc = -EFAULT;
		if (get_user(val, (unsigned char __user *) arg))
			break;
		rc = 0;
		ipxcfg_auto_create_interfaces = val;
		break;
	case SIOCAIPXPRISLT:
		rc = -EFAULT;
		if (get_user(val, (unsigned char __user *) arg))
			break;
		rc = 0;
		ipxcfg_set_auto_select(val);
		break;
	}

	return rc;
}
