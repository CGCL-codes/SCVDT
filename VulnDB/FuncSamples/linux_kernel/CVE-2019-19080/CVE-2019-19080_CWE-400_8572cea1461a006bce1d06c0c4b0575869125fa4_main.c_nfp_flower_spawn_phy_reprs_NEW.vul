static int
nfp_flower_spawn_phy_reprs(struct nfp_app *app, struct nfp_flower_priv *priv)
{
	struct nfp_eth_table *eth_tbl = app->pf->eth_tbl;
	atomic_t *replies = &priv->reify_replies;
	struct nfp_flower_repr_priv *repr_priv;
	struct nfp_repr *nfp_repr;
	struct sk_buff *ctrl_skb;
	struct nfp_reprs *reprs;
	int err, reify_cnt;
	unsigned int i;

	ctrl_skb = nfp_flower_cmsg_mac_repr_start(app, eth_tbl->count);
	if (!ctrl_skb)
		return -ENOMEM;

	reprs = nfp_reprs_alloc(eth_tbl->max_index + 1);
	if (!reprs) {
		err = -ENOMEM;
		goto err_free_ctrl_skb;
	}

	for (i = 0; i < eth_tbl->count; i++) {
		unsigned int phys_port = eth_tbl->ports[i].index;
		struct net_device *repr;
		struct nfp_port *port;
		u32 cmsg_port_id;

		repr = nfp_repr_alloc(app);
		if (!repr) {
			err = -ENOMEM;
			goto err_reprs_clean;
		}

		repr_priv = kzalloc(sizeof(*repr_priv), GFP_KERNEL);
		if (!repr_priv) {
			err = -ENOMEM;
			nfp_repr_free(repr);
			goto err_reprs_clean;
		}

		nfp_repr = netdev_priv(repr);
		nfp_repr->app_priv = repr_priv;
		repr_priv->nfp_repr = nfp_repr;

		port = nfp_port_alloc(app, NFP_PORT_PHYS_PORT, repr);
		if (IS_ERR(port)) {
			err = PTR_ERR(port);
			kfree(repr_priv);
			nfp_repr_free(repr);
			goto err_reprs_clean;
		}
		err = nfp_port_init_phy_port(app->pf, app, port, i);
		if (err) {
			kfree(repr_priv);
			nfp_port_free(port);
			nfp_repr_free(repr);
			goto err_reprs_clean;
		}

		SET_NETDEV_DEV(repr, &priv->nn->pdev->dev);
		nfp_net_get_mac_addr(app->pf, repr, port);

		cmsg_port_id = nfp_flower_cmsg_phys_port(phys_port);
		err = nfp_repr_init(app, repr,
				    cmsg_port_id, port, priv->nn->dp.netdev);
		if (err) {
			kfree(repr_priv);
			nfp_port_free(port);
			nfp_repr_free(repr);
			goto err_reprs_clean;
		}

		nfp_flower_cmsg_mac_repr_add(ctrl_skb, i,
					     eth_tbl->ports[i].nbi,
					     eth_tbl->ports[i].base,
					     phys_port);

		RCU_INIT_POINTER(reprs->reprs[phys_port], repr);
		nfp_info(app->cpp, "Phys Port %d Representor(%s) created\n",
			 phys_port, repr->name);
	}

	nfp_app_reprs_set(app, NFP_REPR_TYPE_PHYS_PORT, reprs);

	/* The REIFY/MAC_REPR control messages should be sent after the MAC
	 * representors are registered using nfp_app_reprs_set().  This is
	 * because the firmware may respond with control messages for the
	 * MAC representors, f.e. to provide the driver with information
	 * about their state, and without registration the driver will drop
	 * any such messages.
	 */
	atomic_set(replies, 0);
	reify_cnt = nfp_flower_reprs_reify(app, NFP_REPR_TYPE_PHYS_PORT, true);
	if (reify_cnt < 0) {
		err = reify_cnt;
		nfp_warn(app->cpp, "Failed to notify firmware about repr creation\n");
		goto err_reprs_remove;
	}

	err = nfp_flower_wait_repr_reify(app, replies, reify_cnt);
	if (err)
		goto err_reprs_remove;

	nfp_ctrl_tx(app->ctrl, ctrl_skb);

	return 0;
err_reprs_remove:
	reprs = nfp_app_reprs_set(app, NFP_REPR_TYPE_PHYS_PORT, NULL);
err_reprs_clean:
	nfp_reprs_clean_and_free(app, reprs);
err_free_ctrl_skb:
	kfree_skb(ctrl_skb);
	return err;
}
