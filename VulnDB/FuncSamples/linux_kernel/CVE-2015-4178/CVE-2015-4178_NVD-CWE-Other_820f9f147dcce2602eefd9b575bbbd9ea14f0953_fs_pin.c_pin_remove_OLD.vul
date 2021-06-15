void pin_remove(struct fs_pin *pin)
{
	spin_lock(&pin_lock);
	hlist_del(&pin->m_list);
	hlist_del(&pin->s_list);
	spin_unlock(&pin_lock);
	spin_lock_irq(&pin->wait.lock);
	pin->done = 1;
	wake_up_locked(&pin->wait);
	spin_unlock_irq(&pin->wait.lock);
}
