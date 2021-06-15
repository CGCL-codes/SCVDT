static void kvm_vcpu_ioctl_x86_get_vcpu_events(struct kvm_vcpu *vcpu,
					       struct kvm_vcpu_events *events)
{
	events->exception.injected =
		vcpu->arch.exception.pending &&
		!kvm_exception_is_soft(vcpu->arch.exception.nr);
	events->exception.nr = vcpu->arch.exception.nr;
	events->exception.has_error_code = vcpu->arch.exception.has_error_code;
	events->exception.pad = 0;
	events->exception.error_code = vcpu->arch.exception.error_code;

	events->interrupt.injected =
		vcpu->arch.interrupt.pending && !vcpu->arch.interrupt.soft;
	events->interrupt.nr = vcpu->arch.interrupt.nr;
	events->interrupt.soft = 0;
	events->interrupt.shadow =
		kvm_x86_ops->get_interrupt_shadow(vcpu,
			KVM_X86_SHADOW_INT_MOV_SS | KVM_X86_SHADOW_INT_STI);

	events->nmi.injected = vcpu->arch.nmi_injected;
	events->nmi.pending = vcpu->arch.nmi_pending;
	events->nmi.masked = kvm_x86_ops->get_nmi_mask(vcpu);
	events->nmi.pad = 0;

	events->sipi_vector = vcpu->arch.sipi_vector;

	events->flags = (KVM_VCPUEVENT_VALID_NMI_PENDING
			 | KVM_VCPUEVENT_VALID_SIPI_VECTOR
			 | KVM_VCPUEVENT_VALID_SHADOW);
	memset(&events->reserved, 0, sizeof(events->reserved));
}
