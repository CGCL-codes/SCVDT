static int dev_ifconf(struct net *net, struct compat_ifconf __user *uifc32)
{
	struct compat_ifconf ifc32;
	struct ifconf ifc;
	struct ifconf __user *uifc;
	struct compat_ifreq __user *ifr32;
	struct ifreq __user *ifr;
	unsigned int i, j;
	int err;

	if (copy_from_user(&ifc32, uifc32, sizeof(struct compat_ifconf)))
		return -EFAULT;

	memset(&ifc, 0, sizeof(ifc));
	if (ifc32.ifcbuf == 0) {
		ifc32.ifc_len = 0;
		ifc.ifc_len = 0;
		ifc.ifc_req = NULL;
		uifc = compat_alloc_user_space(sizeof(struct ifconf));
	} else {
		size_t len = ((ifc32.ifc_len / sizeof(struct compat_ifreq)) + 1) *
			sizeof(struct ifreq);
		uifc = compat_alloc_user_space(sizeof(struct ifconf) + len);
		ifc.ifc_len = len;
		ifr = ifc.ifc_req = (void __user *)(uifc + 1);
		ifr32 = compat_ptr(ifc32.ifcbuf);
		for (i = 0; i < ifc32.ifc_len; i += sizeof(struct compat_ifreq)) {
			if (copy_in_user(ifr, ifr32, sizeof(struct compat_ifreq)))
				return -EFAULT;
			ifr++;
			ifr32++;
		}
	}
	if (copy_to_user(uifc, &ifc, sizeof(struct ifconf)))
		return -EFAULT;

	err = dev_ioctl(net, SIOCGIFCONF, uifc);
	if (err)
		return err;

	if (copy_from_user(&ifc, uifc, sizeof(struct ifconf)))
		return -EFAULT;

	ifr = ifc.ifc_req;
	ifr32 = compat_ptr(ifc32.ifcbuf);
	for (i = 0, j = 0;
	     i + sizeof(struct compat_ifreq) <= ifc32.ifc_len && j < ifc.ifc_len;
	     i += sizeof(struct compat_ifreq), j += sizeof(struct ifreq)) {
		if (copy_in_user(ifr32, ifr, sizeof(struct compat_ifreq)))
			return -EFAULT;
		ifr32++;
		ifr++;
	}

	if (ifc32.ifcbuf == 0) {
		/* Translate from 64-bit structure multiple to
		 * a 32-bit one.
		 */
		i = ifc.ifc_len;
		i = ((i / sizeof(struct ifreq)) * sizeof(struct compat_ifreq));
		ifc32.ifc_len = i;
	} else {
		ifc32.ifc_len = i;
	}
	if (copy_to_user(uifc32, &ifc32, sizeof(struct compat_ifconf)))
		return -EFAULT;

	return 0;
}
