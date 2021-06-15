static int packet_do_bind(struct sock *sk, const char *name, int ifindex,
			  __be16 proto)
{
	struct packet_sock *po = pkt_sk(sk);
	struct net_device *dev_curr;
	__be16 proto_curr;
	bool need_rehook;
	struct net_device *dev = NULL;
	int ret = 0;
	bool unlisted = false;

	if (po->fanout)
		return -EINVAL;

	lock_sock(sk);
	spin_lock(&po->bind_lock);
	rcu_read_lock();

	if (name) {
		dev = dev_get_by_name_rcu(sock_net(sk), name);
		if (!dev) {
			ret = -ENODEV;
			goto out_unlock;
		}
	} else if (ifindex) {
		dev = dev_get_by_index_rcu(sock_net(sk), ifindex);
		if (!dev) {
			ret = -ENODEV;
			goto out_unlock;
		}
	}

	if (dev)
		dev_hold(dev);

	proto_curr = po->prot_hook.type;
	dev_curr = po->prot_hook.dev;

	need_rehook = proto_curr != proto || dev_curr != dev;

	if (need_rehook) {
		if (po->running) {
			rcu_read_unlock();
			__unregister_prot_hook(sk, true);
			rcu_read_lock();
			dev_curr = po->prot_hook.dev;
			if (dev)
				unlisted = !dev_get_by_index_rcu(sock_net(sk),
								 dev->ifindex);
		}

		po->num = proto;
		po->prot_hook.type = proto;

		if (unlikely(unlisted)) {
			dev_put(dev);
			po->prot_hook.dev = NULL;
			po->ifindex = -1;
			packet_cached_dev_reset(po);
		} else {
			po->prot_hook.dev = dev;
			po->ifindex = dev ? dev->ifindex : 0;
			packet_cached_dev_assign(po, dev);
		}
	}
	if (dev_curr)
		dev_put(dev_curr);

	if (proto == 0 || !need_rehook)
		goto out_unlock;

	if (!unlisted && (!dev || (dev->flags & IFF_UP))) {
		register_prot_hook(sk);
	} else {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
	}

out_unlock:
	rcu_read_unlock();
	spin_unlock(&po->bind_lock);
	release_sock(sk);
	return ret;
}
