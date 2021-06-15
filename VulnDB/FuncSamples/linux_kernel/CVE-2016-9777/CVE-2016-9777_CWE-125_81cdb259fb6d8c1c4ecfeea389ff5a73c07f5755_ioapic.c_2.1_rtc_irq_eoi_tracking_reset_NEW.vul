static void rtc_irq_eoi_tracking_reset(struct kvm_ioapic *ioapic)
{
	ioapic->rtc_status.pending_eoi = 0;
	bitmap_zero(ioapic->rtc_status.dest_map.map, KVM_MAX_VCPU_ID);
}
