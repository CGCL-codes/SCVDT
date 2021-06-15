static bool nested_vmx_exit_handled(struct kvm_vcpu *vcpu)
{
	u32 intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	u32 exit_reason = vmx->exit_reason;

	trace_kvm_nested_vmexit(kvm_rip_read(vcpu), exit_reason,
				vmcs_readl(EXIT_QUALIFICATION),
				vmx->idt_vectoring_info,
				intr_info,
				vmcs_read32(VM_EXIT_INTR_ERROR_CODE),
				KVM_ISA_VMX);

	if (vmx->nested.nested_run_pending)
		return 0;

	if (unlikely(vmx->fail)) {
		pr_info_ratelimited("%s failed vm entry %x\n", __func__,
				    vmcs_read32(VM_INSTRUCTION_ERROR));
		return 1;
	}

	switch (exit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		if (!is_exception(intr_info))
			return 0;
		else if (is_page_fault(intr_info))
			return enable_ept;
		else if (is_no_device(intr_info) &&
			 !(vmcs12->guest_cr0 & X86_CR0_TS))
			return 0;
		return vmcs12->exception_bitmap &
				(1u << (intr_info & INTR_INFO_VECTOR_MASK));
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return 0;
	case EXIT_REASON_TRIPLE_FAULT:
		return 1;
	case EXIT_REASON_PENDING_INTERRUPT:
		return nested_cpu_has(vmcs12, CPU_BASED_VIRTUAL_INTR_PENDING);
	case EXIT_REASON_NMI_WINDOW:
		return nested_cpu_has(vmcs12, CPU_BASED_VIRTUAL_NMI_PENDING);
	case EXIT_REASON_TASK_SWITCH:
		return 1;
	case EXIT_REASON_CPUID:
		if (kvm_register_read(vcpu, VCPU_REGS_RAX) == 0xa)
			return 0;
		return 1;
	case EXIT_REASON_HLT:
		return nested_cpu_has(vmcs12, CPU_BASED_HLT_EXITING);
	case EXIT_REASON_INVD:
		return 1;
	case EXIT_REASON_INVLPG:
		return nested_cpu_has(vmcs12, CPU_BASED_INVLPG_EXITING);
	case EXIT_REASON_RDPMC:
		return nested_cpu_has(vmcs12, CPU_BASED_RDPMC_EXITING);
	case EXIT_REASON_RDTSC:
		return nested_cpu_has(vmcs12, CPU_BASED_RDTSC_EXITING);
	case EXIT_REASON_VMCALL: case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH: case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST: case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME: case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMOFF: case EXIT_REASON_VMON:
	case EXIT_REASON_INVEPT:
		/*
		 * VMX instructions trap unconditionally. This allows L1 to
		 * emulate them for its L2 guest, i.e., allows 3-level nesting!
		 */
		return 1;
	case EXIT_REASON_CR_ACCESS:
		return nested_vmx_exit_handled_cr(vcpu, vmcs12);
	case EXIT_REASON_DR_ACCESS:
		return nested_cpu_has(vmcs12, CPU_BASED_MOV_DR_EXITING);
	case EXIT_REASON_IO_INSTRUCTION:
		return nested_vmx_exit_handled_io(vcpu, vmcs12);
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
		return nested_vmx_exit_handled_msr(vcpu, vmcs12, exit_reason);
	case EXIT_REASON_INVALID_STATE:
		return 1;
	case EXIT_REASON_MWAIT_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_MWAIT_EXITING);
	case EXIT_REASON_MONITOR_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_MONITOR_EXITING);
	case EXIT_REASON_PAUSE_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_PAUSE_EXITING) ||
			nested_cpu_has2(vmcs12,
				SECONDARY_EXEC_PAUSE_LOOP_EXITING);
	case EXIT_REASON_MCE_DURING_VMENTRY:
		return 0;
	case EXIT_REASON_TPR_BELOW_THRESHOLD:
		return nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW);
	case EXIT_REASON_APIC_ACCESS:
		return nested_cpu_has2(vmcs12,
			SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES);
	case EXIT_REASON_EPT_VIOLATION:
		/*
		 * L0 always deals with the EPT violation. If nested EPT is
		 * used, and the nested mmu code discovers that the address is
		 * missing in the guest EPT table (EPT12), the EPT violation
		 * will be injected with nested_ept_inject_page_fault()
		 */
		return 0;
	case EXIT_REASON_EPT_MISCONFIG:
		/*
		 * L2 never uses directly L1's EPT, but rather L0's own EPT
		 * table (shadow on EPT) or a merged EPT table that L0 built
		 * (EPT on EPT). So any problems with the structure of the
		 * table is L0's fault.
		 */
		return 0;
	case EXIT_REASON_WBINVD:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_WBINVD_EXITING);
	case EXIT_REASON_XSETBV:
		return 1;
	default:
		return 1;
	}
}
