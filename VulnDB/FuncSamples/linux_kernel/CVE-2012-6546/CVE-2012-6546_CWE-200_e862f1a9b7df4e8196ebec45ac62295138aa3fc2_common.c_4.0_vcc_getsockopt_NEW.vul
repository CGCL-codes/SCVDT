int vcc_getsockopt(struct socket *sock, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	struct atm_vcc *vcc;
	int len;

	if (get_user(len, optlen))
		return -EFAULT;
	if (__SO_LEVEL_MATCH(optname, level) && len != __SO_SIZE(optname))
		return -EINVAL;

	vcc = ATM_SD(sock);
	switch (optname) {
	case SO_ATMQOS:
		if (!test_bit(ATM_VF_HASQOS, &vcc->flags))
			return -EINVAL;
		return copy_to_user(optval, &vcc->qos, sizeof(vcc->qos))
			? -EFAULT : 0;
	case SO_SETCLP:
		return put_user(vcc->atm_options & ATM_ATMOPT_CLP ? 1 : 0,
				(unsigned long __user *)optval) ? -EFAULT : 0;
	case SO_ATMPVC:
	{
		struct sockaddr_atmpvc pvc;

		if (!vcc->dev || !test_bit(ATM_VF_ADDR, &vcc->flags))
			return -ENOTCONN;
		memset(&pvc, 0, sizeof(pvc));
		pvc.sap_family = AF_ATMPVC;
		pvc.sap_addr.itf = vcc->dev->number;
		pvc.sap_addr.vpi = vcc->vpi;
		pvc.sap_addr.vci = vcc->vci;
		return copy_to_user(optval, &pvc, sizeof(pvc)) ? -EFAULT : 0;
	}
	default:
		if (level == SOL_SOCKET)
			return -EINVAL;
		break;
	}
	if (!vcc->dev || !vcc->dev->ops->getsockopt)
		return -EINVAL;
	return vcc->dev->ops->getsockopt(vcc, level, optname, optval, len);
}
