static int pit_ioport_read(struct kvm_io_device *this,
			   gpa_t addr, int len, void *data)
{
	struct kvm_pit *pit = dev_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	int ret, count;
	struct kvm_kpit_channel_state *s;
	if (!pit_in_range(addr))
		return -EOPNOTSUPP;

	addr &= KVM_PIT_CHANNEL_MASK;
	if (addr == 3)
		return 0;

	s = &pit_state->channels[addr];

	mutex_lock(&pit_state->lock);

	if (s->status_latched) {
		s->status_latched = 0;
		ret = s->status;
	} else if (s->count_latched) {
		switch (s->count_latched) {
		default:
		case RW_STATE_LSB:
			ret = s->latched_count & 0xff;
			s->count_latched = 0;
			break;
		case RW_STATE_MSB:
			ret = s->latched_count >> 8;
			s->count_latched = 0;
			break;
		case RW_STATE_WORD0:
			ret = s->latched_count & 0xff;
			s->count_latched = RW_STATE_MSB;
			break;
		}
	} else {
		switch (s->read_state) {
		default:
		case RW_STATE_LSB:
			count = pit_get_count(kvm, addr);
			ret = count & 0xff;
			break;
		case RW_STATE_MSB:
			count = pit_get_count(kvm, addr);
			ret = (count >> 8) & 0xff;
			break;
		case RW_STATE_WORD0:
			count = pit_get_count(kvm, addr);
			ret = count & 0xff;
			s->read_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			count = pit_get_count(kvm, addr);
			ret = (count >> 8) & 0xff;
			s->read_state = RW_STATE_WORD0;
			break;
		}
	}

	if (len > sizeof(ret))
		len = sizeof(ret);
	memcpy(data, (char *)&ret, len);

	mutex_unlock(&pit_state->lock);
	return 0;
}
