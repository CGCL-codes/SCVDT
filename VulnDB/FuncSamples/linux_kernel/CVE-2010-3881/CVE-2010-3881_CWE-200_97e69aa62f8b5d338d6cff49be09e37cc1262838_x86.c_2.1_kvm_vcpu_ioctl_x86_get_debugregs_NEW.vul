static void kvm_vcpu_ioctl_x86_get_debugregs(struct kvm_vcpu *vcpu,
					     struct kvm_debugregs *dbgregs)
{
	memcpy(dbgregs->db, vcpu->arch.db, sizeof(vcpu->arch.db));
	dbgregs->dr6 = vcpu->arch.dr6;
	dbgregs->dr7 = vcpu->arch.dr7;
	dbgregs->flags = 0;
	memset(&dbgregs->reserved, 0, sizeof(dbgregs->reserved));
}
