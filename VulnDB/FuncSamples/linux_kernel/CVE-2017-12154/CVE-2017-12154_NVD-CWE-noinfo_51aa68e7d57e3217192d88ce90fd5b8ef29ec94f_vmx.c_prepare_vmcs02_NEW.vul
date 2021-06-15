static int prepare_vmcs02(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12,
			  bool from_vmentry, u32 *entry_failure_code)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 exec_control, vmcs12_exec_ctrl;

	vmcs_write16(GUEST_ES_SELECTOR, vmcs12->guest_es_selector);
	vmcs_write16(GUEST_CS_SELECTOR, vmcs12->guest_cs_selector);
	vmcs_write16(GUEST_SS_SELECTOR, vmcs12->guest_ss_selector);
	vmcs_write16(GUEST_DS_SELECTOR, vmcs12->guest_ds_selector);
	vmcs_write16(GUEST_FS_SELECTOR, vmcs12->guest_fs_selector);
	vmcs_write16(GUEST_GS_SELECTOR, vmcs12->guest_gs_selector);
	vmcs_write16(GUEST_LDTR_SELECTOR, vmcs12->guest_ldtr_selector);
	vmcs_write16(GUEST_TR_SELECTOR, vmcs12->guest_tr_selector);
	vmcs_write32(GUEST_ES_LIMIT, vmcs12->guest_es_limit);
	vmcs_write32(GUEST_CS_LIMIT, vmcs12->guest_cs_limit);
	vmcs_write32(GUEST_SS_LIMIT, vmcs12->guest_ss_limit);
	vmcs_write32(GUEST_DS_LIMIT, vmcs12->guest_ds_limit);
	vmcs_write32(GUEST_FS_LIMIT, vmcs12->guest_fs_limit);
	vmcs_write32(GUEST_GS_LIMIT, vmcs12->guest_gs_limit);
	vmcs_write32(GUEST_LDTR_LIMIT, vmcs12->guest_ldtr_limit);
	vmcs_write32(GUEST_TR_LIMIT, vmcs12->guest_tr_limit);
	vmcs_write32(GUEST_GDTR_LIMIT, vmcs12->guest_gdtr_limit);
	vmcs_write32(GUEST_IDTR_LIMIT, vmcs12->guest_idtr_limit);
	vmcs_write32(GUEST_ES_AR_BYTES, vmcs12->guest_es_ar_bytes);
	vmcs_write32(GUEST_CS_AR_BYTES, vmcs12->guest_cs_ar_bytes);
	vmcs_write32(GUEST_SS_AR_BYTES, vmcs12->guest_ss_ar_bytes);
	vmcs_write32(GUEST_DS_AR_BYTES, vmcs12->guest_ds_ar_bytes);
	vmcs_write32(GUEST_FS_AR_BYTES, vmcs12->guest_fs_ar_bytes);
	vmcs_write32(GUEST_GS_AR_BYTES, vmcs12->guest_gs_ar_bytes);
	vmcs_write32(GUEST_LDTR_AR_BYTES, vmcs12->guest_ldtr_ar_bytes);
	vmcs_write32(GUEST_TR_AR_BYTES, vmcs12->guest_tr_ar_bytes);
	vmcs_writel(GUEST_ES_BASE, vmcs12->guest_es_base);
	vmcs_writel(GUEST_CS_BASE, vmcs12->guest_cs_base);
	vmcs_writel(GUEST_SS_BASE, vmcs12->guest_ss_base);
	vmcs_writel(GUEST_DS_BASE, vmcs12->guest_ds_base);
	vmcs_writel(GUEST_FS_BASE, vmcs12->guest_fs_base);
	vmcs_writel(GUEST_GS_BASE, vmcs12->guest_gs_base);
	vmcs_writel(GUEST_LDTR_BASE, vmcs12->guest_ldtr_base);
	vmcs_writel(GUEST_TR_BASE, vmcs12->guest_tr_base);
	vmcs_writel(GUEST_GDTR_BASE, vmcs12->guest_gdtr_base);
	vmcs_writel(GUEST_IDTR_BASE, vmcs12->guest_idtr_base);

	if (from_vmentry &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_DEBUG_CONTROLS)) {
		kvm_set_dr(vcpu, 7, vmcs12->guest_dr7);
		vmcs_write64(GUEST_IA32_DEBUGCTL, vmcs12->guest_ia32_debugctl);
	} else {
		kvm_set_dr(vcpu, 7, vcpu->arch.dr7);
		vmcs_write64(GUEST_IA32_DEBUGCTL, vmx->nested.vmcs01_debugctl);
	}
	if (from_vmentry) {
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     vmcs12->vm_entry_intr_info_field);
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE,
			     vmcs12->vm_entry_exception_error_code);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmcs12->vm_entry_instruction_len);
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO,
			     vmcs12->guest_interruptibility_info);
		vmx->loaded_vmcs->nmi_known_unmasked =
			!(vmcs12->guest_interruptibility_info & GUEST_INTR_STATE_NMI);
	} else {
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	}
	vmcs_write32(GUEST_SYSENTER_CS, vmcs12->guest_sysenter_cs);
	vmx_set_rflags(vcpu, vmcs12->guest_rflags);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS,
		vmcs12->guest_pending_dbg_exceptions);
	vmcs_writel(GUEST_SYSENTER_ESP, vmcs12->guest_sysenter_esp);
	vmcs_writel(GUEST_SYSENTER_EIP, vmcs12->guest_sysenter_eip);

	if (nested_cpu_has_xsaves(vmcs12))
		vmcs_write64(XSS_EXIT_BITMAP, vmcs12->xss_exit_bitmap);
	vmcs_write64(VMCS_LINK_POINTER, -1ull);

	exec_control = vmcs12->pin_based_vm_exec_control;

	/* Preemption timer setting is only taken from vmcs01.  */
	exec_control &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
	exec_control |= vmcs_config.pin_based_exec_ctrl;
	if (vmx->hv_deadline_tsc == -1)
		exec_control &= ~PIN_BASED_VMX_PREEMPTION_TIMER;

	/* Posted interrupts setting is only taken from vmcs12.  */
	if (nested_cpu_has_posted_intr(vmcs12)) {
		vmx->nested.posted_intr_nv = vmcs12->posted_intr_nv;
		vmx->nested.pi_pending = false;
		vmcs_write16(POSTED_INTR_NV, POSTED_INTR_NESTED_VECTOR);
	} else {
		exec_control &= ~PIN_BASED_POSTED_INTR;
	}

	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, exec_control);

	vmx->nested.preemption_timer_expired = false;
	if (nested_cpu_has_preemption_timer(vmcs12))
		vmx_start_preemption_timer(vcpu);

	/*
	 * Whether page-faults are trapped is determined by a combination of
	 * 3 settings: PFEC_MASK, PFEC_MATCH and EXCEPTION_BITMAP.PF.
	 * If enable_ept, L0 doesn't care about page faults and we should
	 * set all of these to L1's desires. However, if !enable_ept, L0 does
	 * care about (at least some) page faults, and because it is not easy
	 * (if at all possible?) to merge L0 and L1's desires, we simply ask
	 * to exit on each and every L2 page fault. This is done by setting
	 * MASK=MATCH=0 and (see below) EB.PF=1.
	 * Note that below we don't need special code to set EB.PF beyond the
	 * "or"ing of the EB of vmcs01 and vmcs12, because when enable_ept,
	 * vmcs01's EB.PF is 0 so the "or" will take vmcs12's value, and when
	 * !enable_ept, EB.PF is 1, so the "or" will always be 1.
	 */
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK,
		enable_ept ? vmcs12->page_fault_error_code_mask : 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH,
		enable_ept ? vmcs12->page_fault_error_code_match : 0);

	if (cpu_has_secondary_exec_ctrls()) {
		exec_control = vmx->secondary_exec_control;

		/* Take the following fields only from vmcs12 */
		exec_control &= ~(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
				  SECONDARY_EXEC_ENABLE_INVPCID |
				  SECONDARY_EXEC_RDTSCP |
				  SECONDARY_EXEC_XSAVES |
				  SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
				  SECONDARY_EXEC_APIC_REGISTER_VIRT |
				  SECONDARY_EXEC_ENABLE_VMFUNC);
		if (nested_cpu_has(vmcs12,
				   CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)) {
			vmcs12_exec_ctrl = vmcs12->secondary_vm_exec_control &
				~SECONDARY_EXEC_ENABLE_PML;
			exec_control |= vmcs12_exec_ctrl;
		}

		/* All VMFUNCs are currently emulated through L0 vmexits.  */
		if (exec_control & SECONDARY_EXEC_ENABLE_VMFUNC)
			vmcs_write64(VM_FUNCTION_CONTROL, 0);

		if (exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY) {
			vmcs_write64(EOI_EXIT_BITMAP0,
				vmcs12->eoi_exit_bitmap0);
			vmcs_write64(EOI_EXIT_BITMAP1,
				vmcs12->eoi_exit_bitmap1);
			vmcs_write64(EOI_EXIT_BITMAP2,
				vmcs12->eoi_exit_bitmap2);
			vmcs_write64(EOI_EXIT_BITMAP3,
				vmcs12->eoi_exit_bitmap3);
			vmcs_write16(GUEST_INTR_STATUS,
				vmcs12->guest_intr_status);
		}

		/*
		 * Write an illegal value to APIC_ACCESS_ADDR. Later,
		 * nested_get_vmcs12_pages will either fix it up or
		 * remove the VM execution control.
		 */
		if (exec_control & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)
			vmcs_write64(APIC_ACCESS_ADDR, -1ull);

		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, exec_control);
	}


	/*
	 * Set host-state according to L0's settings (vmcs12 is irrelevant here)
	 * Some constant fields are set here by vmx_set_constant_host_state().
	 * Other fields are different per CPU, and will be set later when
	 * vmx_vcpu_load() is called, and when vmx_save_host_state() is called.
	 */
	vmx_set_constant_host_state(vmx);

	/*
	 * Set the MSR load/store lists to match L0's settings.
	 */
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vmx->msr_autoload.nr);
	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.host));
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vmx->msr_autoload.nr);
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.guest));

	/*
	 * HOST_RSP is normally set correctly in vmx_vcpu_run() just before
	 * entry, but only if the current (host) sp changed from the value
	 * we wrote last (vmx->host_rsp). This cache is no longer relevant
	 * if we switch vmcs, and rather than hold a separate cache per vmcs,
	 * here we just force the write to happen on entry.
	 */
	vmx->host_rsp = 0;

	exec_control = vmx_exec_control(vmx); /* L0's desires */
	exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	exec_control &= ~CPU_BASED_TPR_SHADOW;
	exec_control |= vmcs12->cpu_based_vm_exec_control;

	/*
	 * Write an illegal value to VIRTUAL_APIC_PAGE_ADDR. Later, if
	 * nested_get_vmcs12_pages can't fix it up, the illegal value
	 * will result in a VM entry failure.
	 */
	if (exec_control & CPU_BASED_TPR_SHADOW) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, -1ull);
		vmcs_write32(TPR_THRESHOLD, vmcs12->tpr_threshold);
	} else {
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_LOAD_EXITING |
				CPU_BASED_CR8_STORE_EXITING;
#endif
	}

	/*
	 * Merging of IO bitmap not currently supported.
	 * Rather, exit every time.
	 */
	exec_control &= ~CPU_BASED_USE_IO_BITMAPS;
	exec_control |= CPU_BASED_UNCOND_IO_EXITING;

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);

	/* EXCEPTION_BITMAP and CR0_GUEST_HOST_MASK should basically be the
	 * bitwise-or of what L1 wants to trap for L2, and what we want to
	 * trap. Note that CR0.TS also needs updating - we do this later.
	 */
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits &= ~vmcs12->cr0_guest_host_mask;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);

	/* L2->L1 exit controls are emulated - the hardware exit is to L0 so
	 * we should use its exit controls. Note that VM_EXIT_LOAD_IA32_EFER
	 * bits are further modified by vmx_set_efer() below.
	 */
	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);

	/* vmcs12's VM_ENTRY_LOAD_IA32_EFER and VM_ENTRY_IA32E_MODE are
	 * emulated by vmx_set_efer(), below.
	 */
	vm_entry_controls_init(vmx, 
		(vmcs12->vm_entry_controls & ~VM_ENTRY_LOAD_IA32_EFER &
			~VM_ENTRY_IA32E_MODE) |
		(vmcs_config.vmentry_ctrl & ~VM_ENTRY_IA32E_MODE));

	if (from_vmentry &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_PAT)) {
		vmcs_write64(GUEST_IA32_PAT, vmcs12->guest_ia32_pat);
		vcpu->arch.pat = vmcs12->guest_ia32_pat;
	} else if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
		vmcs_write64(GUEST_IA32_PAT, vmx->vcpu.arch.pat);
	}

	set_cr4_guest_host_mask(vmx);

	if (from_vmentry &&
	    vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS)
		vmcs_write64(GUEST_BNDCFGS, vmcs12->guest_bndcfgs);

	if (vmcs12->cpu_based_vm_exec_control & CPU_BASED_USE_TSC_OFFSETING)
		vmcs_write64(TSC_OFFSET,
			vcpu->arch.tsc_offset + vmcs12->tsc_offset);
	else
		vmcs_write64(TSC_OFFSET, vcpu->arch.tsc_offset);
	if (kvm_has_tsc_control)
		decache_tsc_multiplier(vmx);

	if (enable_vpid) {
		/*
		 * There is no direct mapping between vpid02 and vpid12, the
		 * vpid02 is per-vCPU for L0 and reused while the value of
		 * vpid12 is changed w/ one invvpid during nested vmentry.
		 * The vpid12 is allocated by L1 for L2, so it will not
		 * influence global bitmap(for vpid01 and vpid02 allocation)
		 * even if spawn a lot of nested vCPUs.
		 */
		if (nested_cpu_has_vpid(vmcs12) && vmx->nested.vpid02) {
			vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->nested.vpid02);
			if (vmcs12->virtual_processor_id != vmx->nested.last_vpid) {
				vmx->nested.last_vpid = vmcs12->virtual_processor_id;
				__vmx_flush_tlb(vcpu, to_vmx(vcpu)->nested.vpid02);
			}
		} else {
			vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);
			vmx_flush_tlb(vcpu);
		}

	}

	if (enable_pml) {
		/*
		 * Conceptually we want to copy the PML address and index from
		 * vmcs01 here, and then back to vmcs01 on nested vmexit. But,
		 * since we always flush the log on each vmexit, this happens
		 * to be equivalent to simply resetting the fields in vmcs02.
		 */
		ASSERT(vmx->pml_pg);
		vmcs_write64(PML_ADDRESS, page_to_phys(vmx->pml_pg));
		vmcs_write16(GUEST_PML_INDEX, PML_ENTITY_NUM - 1);
	}

	if (nested_cpu_has_ept(vmcs12)) {
		if (nested_ept_init_mmu_context(vcpu)) {
			*entry_failure_code = ENTRY_FAIL_DEFAULT;
			return 1;
		}
	} else if (nested_cpu_has2(vmcs12,
				   SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)) {
		vmx_flush_tlb_ept_only(vcpu);
	}

	/*
	 * This sets GUEST_CR0 to vmcs12->guest_cr0, possibly modifying those
	 * bits which we consider mandatory enabled.
	 * The CR0_READ_SHADOW is what L2 should have expected to read given
	 * the specifications by L1; It's not enough to take
	 * vmcs12->cr0_read_shadow because on our cr0_guest_host_mask we we
	 * have more bits than L1 expected.
	 */
	vmx_set_cr0(vcpu, vmcs12->guest_cr0);
	vmcs_writel(CR0_READ_SHADOW, nested_read_cr0(vmcs12));

	vmx_set_cr4(vcpu, vmcs12->guest_cr4);
	vmcs_writel(CR4_READ_SHADOW, nested_read_cr4(vmcs12));

	if (from_vmentry &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_EFER))
		vcpu->arch.efer = vmcs12->guest_ia32_efer;
	else if (vmcs12->vm_entry_controls & VM_ENTRY_IA32E_MODE)
		vcpu->arch.efer |= (EFER_LMA | EFER_LME);
	else
		vcpu->arch.efer &= ~(EFER_LMA | EFER_LME);
	/* Note: modifies VM_ENTRY/EXIT_CONTROLS and GUEST/HOST_IA32_EFER */
	vmx_set_efer(vcpu, vcpu->arch.efer);

	/* Shadow page tables on either EPT or shadow page tables. */
	if (nested_vmx_load_cr3(vcpu, vmcs12->guest_cr3, nested_cpu_has_ept(vmcs12),
				entry_failure_code))
		return 1;

	if (!enable_ept)
		vcpu->arch.walk_mmu->inject_page_fault = vmx_inject_page_fault_nested;

	/*
	 * L1 may access the L2's PDPTR, so save them to construct vmcs12
	 */
	if (enable_ept) {
		vmcs_write64(GUEST_PDPTR0, vmcs12->guest_pdptr0);
		vmcs_write64(GUEST_PDPTR1, vmcs12->guest_pdptr1);
		vmcs_write64(GUEST_PDPTR2, vmcs12->guest_pdptr2);
		vmcs_write64(GUEST_PDPTR3, vmcs12->guest_pdptr3);
	}

	kvm_register_write(vcpu, VCPU_REGS_RSP, vmcs12->guest_rsp);
	kvm_register_write(vcpu, VCPU_REGS_RIP, vmcs12->guest_rip);
	return 0;
}
