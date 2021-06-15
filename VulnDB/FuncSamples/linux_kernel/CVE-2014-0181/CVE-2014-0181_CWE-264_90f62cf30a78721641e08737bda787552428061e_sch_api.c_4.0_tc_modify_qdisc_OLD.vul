static int tc_modify_qdisc(struct sk_buff *skb, struct nlmsghdr *n)
{
	struct net *net = sock_net(skb->sk);
	struct tcmsg *tcm;
	struct nlattr *tca[TCA_MAX + 1];
	struct net_device *dev;
	u32 clid;
	struct Qdisc *q, *p;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

replay:
	/* Reinit, just in case something touches this. */
	err = nlmsg_parse(n, sizeof(*tcm), tca, TCA_MAX, NULL);
	if (err < 0)
		return err;

	tcm = nlmsg_data(n);
	clid = tcm->tcm_parent;
	q = p = NULL;

	dev = __dev_get_by_index(net, tcm->tcm_ifindex);
	if (!dev)
		return -ENODEV;


	if (clid) {
		if (clid != TC_H_ROOT) {
			if (clid != TC_H_INGRESS) {
				p = qdisc_lookup(dev, TC_H_MAJ(clid));
				if (!p)
					return -ENOENT;
				q = qdisc_leaf(p, clid);
			} else if (dev_ingress_queue_create(dev)) {
				q = dev_ingress_queue(dev)->qdisc_sleeping;
			}
		} else {
			q = dev->qdisc;
		}

		/* It may be default qdisc, ignore it */
		if (q && q->handle == 0)
			q = NULL;

		if (!q || !tcm->tcm_handle || q->handle != tcm->tcm_handle) {
			if (tcm->tcm_handle) {
				if (q && !(n->nlmsg_flags & NLM_F_REPLACE))
					return -EEXIST;
				if (TC_H_MIN(tcm->tcm_handle))
					return -EINVAL;
				q = qdisc_lookup(dev, tcm->tcm_handle);
				if (!q)
					goto create_n_graft;
				if (n->nlmsg_flags & NLM_F_EXCL)
					return -EEXIST;
				if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id))
					return -EINVAL;
				if (q == p ||
				    (p && check_loop(q, p, 0)))
					return -ELOOP;
				atomic_inc(&q->refcnt);
				goto graft;
			} else {
				if (!q)
					goto create_n_graft;

				/* This magic test requires explanation.
				 *
				 *   We know, that some child q is already
				 *   attached to this parent and have choice:
				 *   either to change it or to create/graft new one.
				 *
				 *   1. We are allowed to create/graft only
				 *   if CREATE and REPLACE flags are set.
				 *
				 *   2. If EXCL is set, requestor wanted to say,
				 *   that qdisc tcm_handle is not expected
				 *   to exist, so that we choose create/graft too.
				 *
				 *   3. The last case is when no flags are set.
				 *   Alas, it is sort of hole in API, we
				 *   cannot decide what to do unambiguously.
				 *   For now we select create/graft, if
				 *   user gave KIND, which does not match existing.
				 */
				if ((n->nlmsg_flags & NLM_F_CREATE) &&
				    (n->nlmsg_flags & NLM_F_REPLACE) &&
				    ((n->nlmsg_flags & NLM_F_EXCL) ||
				     (tca[TCA_KIND] &&
				      nla_strcmp(tca[TCA_KIND], q->ops->id))))
					goto create_n_graft;
			}
		}
	} else {
		if (!tcm->tcm_handle)
			return -EINVAL;
		q = qdisc_lookup(dev, tcm->tcm_handle);
	}

	/* Change qdisc parameters */
	if (q == NULL)
		return -ENOENT;
	if (n->nlmsg_flags & NLM_F_EXCL)
		return -EEXIST;
	if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], q->ops->id))
		return -EINVAL;
	err = qdisc_change(q, tca);
	if (err == 0)
		qdisc_notify(net, skb, n, clid, NULL, q);
	return err;

create_n_graft:
	if (!(n->nlmsg_flags & NLM_F_CREATE))
		return -ENOENT;
	if (clid == TC_H_INGRESS) {
		if (dev_ingress_queue(dev))
			q = qdisc_create(dev, dev_ingress_queue(dev), p,
					 tcm->tcm_parent, tcm->tcm_parent,
					 tca, &err);
		else
			err = -ENOENT;
	} else {
		struct netdev_queue *dev_queue;

		if (p && p->ops->cl_ops && p->ops->cl_ops->select_queue)
			dev_queue = p->ops->cl_ops->select_queue(p, tcm);
		else if (p)
			dev_queue = p->dev_queue;
		else
			dev_queue = netdev_get_tx_queue(dev, 0);

		q = qdisc_create(dev, dev_queue, p,
				 tcm->tcm_parent, tcm->tcm_handle,
				 tca, &err);
	}
	if (q == NULL) {
		if (err == -EAGAIN)
			goto replay;
		return err;
	}

graft:
	err = qdisc_graft(dev, p, skb, n, clid, q, NULL);
	if (err) {
		if (q)
			qdisc_destroy(q);
		return err;
	}

	return 0;
}
