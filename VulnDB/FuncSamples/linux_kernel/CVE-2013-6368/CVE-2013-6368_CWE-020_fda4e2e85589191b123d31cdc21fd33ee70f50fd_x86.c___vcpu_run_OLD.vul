static int __vcpu_run(struct kvm_vcpu *vcpu)
{
	int r;
	struct kvm *kvm = vcpu->kvm;

	vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
	r = vapic_enter(vcpu);
	if (r) {
		srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
		return r;
	}

	r = 1;
	while (r > 0) {
		if (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE &&
		    !vcpu->arch.apf.halted)
			r = vcpu_enter_guest(vcpu);
		else {
			srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
			kvm_vcpu_block(vcpu);
			vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
			if (kvm_check_request(KVM_REQ_UNHALT, vcpu)) {
				kvm_apic_accept_events(vcpu);
				switch(vcpu->arch.mp_state) {
				case KVM_MP_STATE_HALTED:
					vcpu->arch.pv.pv_unhalted = false;
					vcpu->arch.mp_state =
						KVM_MP_STATE_RUNNABLE;
				case KVM_MP_STATE_RUNNABLE:
					vcpu->arch.apf.halted = false;
					break;
				case KVM_MP_STATE_INIT_RECEIVED:
					break;
				default:
					r = -EINTR;
					break;
				}
			}
		}

		if (r <= 0)
			break;

		clear_bit(KVM_REQ_PENDING_TIMER, &vcpu->requests);
		if (kvm_cpu_has_pending_timer(vcpu))
			kvm_inject_pending_timer_irqs(vcpu);

		if (dm_request_for_irq_injection(vcpu)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			++vcpu->stat.request_irq_exits;
		}

		kvm_check_async_pf_completion(vcpu);

		if (signal_pending(current)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			++vcpu->stat.signal_exits;
		}
		if (need_resched()) {
			srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
			kvm_resched(vcpu);
			vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
		}
	}

	srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);

	vapic_exit(vcpu);

	return r;
}
