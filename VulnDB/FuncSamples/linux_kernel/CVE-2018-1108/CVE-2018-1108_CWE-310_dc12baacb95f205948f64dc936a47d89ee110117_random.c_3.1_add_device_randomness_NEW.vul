void add_device_randomness(const void *buf, unsigned int size)
{
	unsigned long time = random_get_entropy() ^ jiffies;
	unsigned long flags;

	if (!crng_ready() && size)
		crng_slow_load(buf, size);

	trace_add_device_randomness(size, _RET_IP_);
	spin_lock_irqsave(&input_pool.lock, flags);
	_mix_pool_bytes(&input_pool, buf, size);
	_mix_pool_bytes(&input_pool, &time, sizeof(time));
	spin_unlock_irqrestore(&input_pool.lock, flags);
}
