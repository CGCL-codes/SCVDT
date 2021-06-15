void kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr)
{
	vcpu->arch.apic->vapic_addr = vapic_addr;
	if (vapic_addr)
		__set_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention);
	else
		__clear_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention);
}
