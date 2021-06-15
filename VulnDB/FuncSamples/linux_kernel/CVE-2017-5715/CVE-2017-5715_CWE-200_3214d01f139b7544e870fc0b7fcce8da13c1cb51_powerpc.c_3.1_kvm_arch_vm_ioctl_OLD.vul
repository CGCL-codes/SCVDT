long kvm_arch_vm_ioctl(struct file *filp,
                       unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm __maybe_unused = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r;

	switch (ioctl) {
	case KVM_PPC_GET_PVINFO: {
		struct kvm_ppc_pvinfo pvinfo;
		memset(&pvinfo, 0, sizeof(pvinfo));
		r = kvm_vm_ioctl_get_pvinfo(&pvinfo);
		if (copy_to_user(argp, &pvinfo, sizeof(pvinfo))) {
			r = -EFAULT;
			goto out;
		}

		break;
	}
	case KVM_ENABLE_CAP:
	{
		struct kvm_enable_cap cap;
		r = -EFAULT;
		if (copy_from_user(&cap, argp, sizeof(cap)))
			goto out;
		r = kvm_vm_ioctl_enable_cap(kvm, &cap);
		break;
	}
#ifdef CONFIG_SPAPR_TCE_IOMMU
	case KVM_CREATE_SPAPR_TCE_64: {
		struct kvm_create_spapr_tce_64 create_tce_64;

		r = -EFAULT;
		if (copy_from_user(&create_tce_64, argp, sizeof(create_tce_64)))
			goto out;
		if (create_tce_64.flags) {
			r = -EINVAL;
			goto out;
		}
		r = kvm_vm_ioctl_create_spapr_tce(kvm, &create_tce_64);
		goto out;
	}
	case KVM_CREATE_SPAPR_TCE: {
		struct kvm_create_spapr_tce create_tce;
		struct kvm_create_spapr_tce_64 create_tce_64;

		r = -EFAULT;
		if (copy_from_user(&create_tce, argp, sizeof(create_tce)))
			goto out;

		create_tce_64.liobn = create_tce.liobn;
		create_tce_64.page_shift = IOMMU_PAGE_SHIFT_4K;
		create_tce_64.offset = 0;
		create_tce_64.size = create_tce.window_size >>
				IOMMU_PAGE_SHIFT_4K;
		create_tce_64.flags = 0;
		r = kvm_vm_ioctl_create_spapr_tce(kvm, &create_tce_64);
		goto out;
	}
#endif
#ifdef CONFIG_PPC_BOOK3S_64
	case KVM_PPC_GET_SMMU_INFO: {
		struct kvm_ppc_smmu_info info;
		struct kvm *kvm = filp->private_data;

		memset(&info, 0, sizeof(info));
		r = kvm->arch.kvm_ops->get_smmu_info(kvm, &info);
		if (r >= 0 && copy_to_user(argp, &info, sizeof(info)))
			r = -EFAULT;
		break;
	}
	case KVM_PPC_RTAS_DEFINE_TOKEN: {
		struct kvm *kvm = filp->private_data;

		r = kvm_vm_ioctl_rtas_define_token(kvm, argp);
		break;
	}
	case KVM_PPC_CONFIGURE_V3_MMU: {
		struct kvm *kvm = filp->private_data;
		struct kvm_ppc_mmuv3_cfg cfg;

		r = -EINVAL;
		if (!kvm->arch.kvm_ops->configure_mmu)
			goto out;
		r = -EFAULT;
		if (copy_from_user(&cfg, argp, sizeof(cfg)))
			goto out;
		r = kvm->arch.kvm_ops->configure_mmu(kvm, &cfg);
		break;
	}
	case KVM_PPC_GET_RMMU_INFO: {
		struct kvm *kvm = filp->private_data;
		struct kvm_ppc_rmmu_info info;

		r = -EINVAL;
		if (!kvm->arch.kvm_ops->get_rmmu_info)
			goto out;
		r = kvm->arch.kvm_ops->get_rmmu_info(kvm, &info);
		if (r >= 0 && copy_to_user(argp, &info, sizeof(info)))
			r = -EFAULT;
		break;
	}
	default: {
		struct kvm *kvm = filp->private_data;
		r = kvm->arch.kvm_ops->arch_vm_ioctl(filp, ioctl, arg);
	}
#else /* CONFIG_PPC_BOOK3S_64 */
	default:
		r = -ENOTTY;
#endif
	}
out:
	return r;
}
