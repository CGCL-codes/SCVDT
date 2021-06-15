int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;
	/* Assume we're using HV mode when the HV module is loaded */
	int hv_enabled = kvmppc_hv_ops ? 1 : 0;

	if (kvm) {
		/*
		 * Hooray - we know which VM type we're running on. Depend on
		 * that rather than the guess above.
		 */
		hv_enabled = is_kvmppc_hv_enabled(kvm);
	}

	switch (ext) {
#ifdef CONFIG_BOOKE
	case KVM_CAP_PPC_BOOKE_SREGS:
	case KVM_CAP_PPC_BOOKE_WATCHDOG:
	case KVM_CAP_PPC_EPR:
#else
	case KVM_CAP_PPC_SEGSTATE:
	case KVM_CAP_PPC_HIOR:
	case KVM_CAP_PPC_PAPR:
#endif
	case KVM_CAP_PPC_UNSET_IRQ:
	case KVM_CAP_PPC_IRQ_LEVEL:
	case KVM_CAP_ENABLE_CAP:
	case KVM_CAP_ENABLE_CAP_VM:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_DEVICE_CTRL:
	case KVM_CAP_IMMEDIATE_EXIT:
		r = 1;
		break;
	case KVM_CAP_PPC_PAIRED_SINGLES:
	case KVM_CAP_PPC_OSI:
	case KVM_CAP_PPC_GET_PVINFO:
#if defined(CONFIG_KVM_E500V2) || defined(CONFIG_KVM_E500MC)
	case KVM_CAP_SW_TLB:
#endif
		/* We support this only for PR */
		r = !hv_enabled;
		break;
#ifdef CONFIG_KVM_MPIC
	case KVM_CAP_IRQ_MPIC:
		r = 1;
		break;
#endif

#ifdef CONFIG_PPC_BOOK3S_64
	case KVM_CAP_SPAPR_TCE:
	case KVM_CAP_SPAPR_TCE_64:
		/* fallthrough */
	case KVM_CAP_SPAPR_TCE_VFIO:
	case KVM_CAP_PPC_RTAS:
	case KVM_CAP_PPC_FIXUP_HCALL:
	case KVM_CAP_PPC_ENABLE_HCALL:
#ifdef CONFIG_KVM_XICS
	case KVM_CAP_IRQ_XICS:
#endif
		r = 1;
		break;

	case KVM_CAP_PPC_ALLOC_HTAB:
		r = hv_enabled;
		break;
#endif /* CONFIG_PPC_BOOK3S_64 */
#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
	case KVM_CAP_PPC_SMT:
		r = 0;
		if (kvm) {
			if (kvm->arch.emul_smt_mode > 1)
				r = kvm->arch.emul_smt_mode;
			else
				r = kvm->arch.smt_mode;
		} else if (hv_enabled) {
			if (cpu_has_feature(CPU_FTR_ARCH_300))
				r = 1;
			else
				r = threads_per_subcore;
		}
		break;
	case KVM_CAP_PPC_SMT_POSSIBLE:
		r = 1;
		if (hv_enabled) {
			if (!cpu_has_feature(CPU_FTR_ARCH_300))
				r = ((threads_per_subcore << 1) - 1);
			else
				/* P9 can emulate dbells, so allow any mode */
				r = 8 | 4 | 2 | 1;
		}
		break;
	case KVM_CAP_PPC_RMA:
		r = 0;
		break;
	case KVM_CAP_PPC_HWRNG:
		r = kvmppc_hwrng_present();
		break;
	case KVM_CAP_PPC_MMU_RADIX:
		r = !!(hv_enabled && radix_enabled());
		break;
	case KVM_CAP_PPC_MMU_HASH_V3:
		r = !!(hv_enabled && !radix_enabled() &&
		       cpu_has_feature(CPU_FTR_ARCH_300));
		break;
#endif
	case KVM_CAP_SYNC_MMU:
#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
		r = hv_enabled;
#elif defined(KVM_ARCH_WANT_MMU_NOTIFIER)
		r = 1;
#else
		r = 0;
#endif
		break;
#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
	case KVM_CAP_PPC_HTAB_FD:
		r = hv_enabled;
		break;
#endif
	case KVM_CAP_NR_VCPUS:
		/*
		 * Recommending a number of CPUs is somewhat arbitrary; we
		 * return the number of present CPUs for -HV (since a host
		 * will have secondary threads "offline"), and for other KVM
		 * implementations just count online CPUs.
		 */
		if (hv_enabled)
			r = num_present_cpus();
		else
			r = num_online_cpus();
		break;
	case KVM_CAP_NR_MEMSLOTS:
		r = KVM_USER_MEM_SLOTS;
		break;
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
#ifdef CONFIG_PPC_BOOK3S_64
	case KVM_CAP_PPC_GET_SMMU_INFO:
		r = 1;
		break;
	case KVM_CAP_SPAPR_MULTITCE:
		r = 1;
		break;
	case KVM_CAP_SPAPR_RESIZE_HPT:
		/* Disable this on POWER9 until code handles new HPTE format */
		r = !!hv_enabled && !cpu_has_feature(CPU_FTR_ARCH_300);
		break;
#endif
#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
	case KVM_CAP_PPC_FWNMI:
		r = hv_enabled;
		break;
#endif
	case KVM_CAP_PPC_HTM:
		r = cpu_has_feature(CPU_FTR_TM_COMP) && hv_enabled;
		break;
	default:
		r = 0;
		break;
	}
	return r;

}
