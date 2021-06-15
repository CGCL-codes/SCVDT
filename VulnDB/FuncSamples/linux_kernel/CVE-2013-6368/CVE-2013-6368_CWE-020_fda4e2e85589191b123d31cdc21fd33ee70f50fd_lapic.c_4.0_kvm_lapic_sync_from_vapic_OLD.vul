void kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu)
{
	u32 data;
	void *vapic;

	if (test_bit(KVM_APIC_PV_EOI_PENDING, &vcpu->arch.apic_attention))
		apic_sync_pv_eoi_from_guest(vcpu, vcpu->arch.apic);

	if (!test_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention))
		return;

	vapic = kmap_atomic(vcpu->arch.apic->vapic_page);
	data = *(u32 *)(vapic + offset_in_page(vcpu->arch.apic->vapic_addr));
	kunmap_atomic(vapic);

	apic_set_tpr(vcpu->arch.apic, data & 0xff);
}
