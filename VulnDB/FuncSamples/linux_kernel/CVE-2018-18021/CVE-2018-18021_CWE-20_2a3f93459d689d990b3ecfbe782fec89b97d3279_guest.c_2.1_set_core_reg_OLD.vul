static int set_core_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	__u32 __user *uaddr = (__u32 __user *)(unsigned long)reg->addr;
	struct kvm_regs *regs = vcpu_gp_regs(vcpu);
	int nr_regs = sizeof(*regs) / sizeof(__u32);
	__uint128_t tmp;
	void *valp = &tmp;
	u64 off;
	int err = 0;

	/* Our ID is an index into the kvm_regs struct. */
	off = core_reg_offset_from_id(reg->id);
	if (off >= nr_regs ||
	    (off + (KVM_REG_SIZE(reg->id) / sizeof(__u32))) >= nr_regs)
		return -ENOENT;

	if (validate_core_offset(reg))
		return -EINVAL;

	if (KVM_REG_SIZE(reg->id) > sizeof(tmp))
		return -EINVAL;

	if (copy_from_user(valp, uaddr, KVM_REG_SIZE(reg->id))) {
		err = -EFAULT;
		goto out;
	}

	if (off == KVM_REG_ARM_CORE_REG(regs.pstate)) {
		u32 mode = (*(u32 *)valp) & PSR_AA32_MODE_MASK;
		switch (mode) {
		case PSR_AA32_MODE_USR:
		case PSR_AA32_MODE_FIQ:
		case PSR_AA32_MODE_IRQ:
		case PSR_AA32_MODE_SVC:
		case PSR_AA32_MODE_ABT:
		case PSR_AA32_MODE_UND:
		case PSR_MODE_EL0t:
		case PSR_MODE_EL1t:
		case PSR_MODE_EL1h:
			break;
		default:
			err = -EINVAL;
			goto out;
		}
	}

	memcpy((u32 *)regs + off, valp, KVM_REG_SIZE(reg->id));
out:
	return err;
}
