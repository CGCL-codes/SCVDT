static void vmx_set_msr_bitmap(struct kvm_vcpu *vcpu)
{
	unsigned long *msr_bitmap;

	if (is_guest_mode(vcpu))
		msr_bitmap = vmx_msr_bitmap_nested;
	else if (vcpu->arch.apic_base & X2APIC_ENABLE) {
		if (is_long_mode(vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode_x2apic;
		else
			msr_bitmap = vmx_msr_bitmap_legacy_x2apic;
	} else {
		if (is_long_mode(vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode;
		else
			msr_bitmap = vmx_msr_bitmap_legacy;
	}

	vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));
}
