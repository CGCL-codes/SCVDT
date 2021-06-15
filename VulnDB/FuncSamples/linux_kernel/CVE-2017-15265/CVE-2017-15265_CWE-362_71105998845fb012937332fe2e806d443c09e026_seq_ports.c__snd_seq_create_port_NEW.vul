struct snd_seq_client_port *snd_seq_create_port(struct snd_seq_client *client,
						int port)
{
	unsigned long flags;
	struct snd_seq_client_port *new_port, *p;
	int num = -1;
	
	/* sanity check */
	if (snd_BUG_ON(!client))
		return NULL;

	if (client->num_ports >= SNDRV_SEQ_MAX_PORTS) {
		pr_warn("ALSA: seq: too many ports for client %d\n", client->number);
		return NULL;
	}

	/* create a new port */
	new_port = kzalloc(sizeof(*new_port), GFP_KERNEL);
	if (!new_port)
		return NULL;	/* failure, out of memory */
	/* init port data */
	new_port->addr.client = client->number;
	new_port->addr.port = -1;
	new_port->owner = THIS_MODULE;
	sprintf(new_port->name, "port-%d", num);
	snd_use_lock_init(&new_port->use_lock);
	port_subs_info_init(&new_port->c_src);
	port_subs_info_init(&new_port->c_dest);
	snd_use_lock_use(&new_port->use_lock);

	num = port >= 0 ? port : 0;
	mutex_lock(&client->ports_mutex);
	write_lock_irqsave(&client->ports_lock, flags);
	list_for_each_entry(p, &client->ports_list_head, list) {
		if (p->addr.port > num)
			break;
		if (port < 0) /* auto-probe mode */
			num = p->addr.port + 1;
	}
	/* insert the new port */
	list_add_tail(&new_port->list, &p->list);
	client->num_ports++;
	new_port->addr.port = num;	/* store the port number in the port */
	sprintf(new_port->name, "port-%d", num);
	write_unlock_irqrestore(&client->ports_lock, flags);
	mutex_unlock(&client->ports_mutex);

	return new_port;
}
