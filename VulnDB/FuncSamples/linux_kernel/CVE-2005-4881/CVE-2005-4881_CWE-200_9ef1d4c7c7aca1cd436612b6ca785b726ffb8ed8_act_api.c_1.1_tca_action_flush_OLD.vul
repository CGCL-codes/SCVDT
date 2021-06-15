static int tca_action_flush(struct rtattr *rta, struct nlmsghdr *n, u32 pid)
{
	struct sk_buff *skb;
	unsigned char *b;
	struct nlmsghdr *nlh;
	struct tcamsg *t;
	struct netlink_callback dcb;
	struct rtattr *x;
	struct rtattr *tb[TCA_ACT_MAX+1];
	struct rtattr *kind;
	struct tc_action *a = create_a(0);
	int err = -EINVAL;

	if (a == NULL) {
		printk("tca_action_flush: couldnt create tc_action\n");
		return err;
	}

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		printk("tca_action_flush: failed skb alloc\n");
		kfree(a);
		return -ENOBUFS;
	}

	b = (unsigned char *)skb->tail;

	if (rtattr_parse_nested(tb, TCA_ACT_MAX, rta) < 0)
		goto err_out;

	kind = tb[TCA_ACT_KIND-1];
	a->ops = tc_lookup_action(kind);
	if (a->ops == NULL)
		goto err_out;

	nlh = NLMSG_PUT(skb, pid, n->nlmsg_seq, RTM_DELACTION, sizeof(*t));
	t = NLMSG_DATA(nlh);
	t->tca_family = AF_UNSPEC;

	x = (struct rtattr *) skb->tail;
	RTA_PUT(skb, TCA_ACT_TAB, 0, NULL);

	err = a->ops->walk(skb, &dcb, RTM_DELACTION, a);
	if (err < 0)
		goto rtattr_failure;

	x->rta_len = skb->tail - (u8 *) x;

	nlh->nlmsg_len = skb->tail - b;
	nlh->nlmsg_flags |= NLM_F_ROOT;
	module_put(a->ops->owner);
	kfree(a);
	err = rtnetlink_send(skb, pid, RTMGRP_TC, n->nlmsg_flags&NLM_F_ECHO);
	if (err > 0)
		return 0;

	return err;

rtattr_failure:
	module_put(a->ops->owner);
nlmsg_failure:
err_out:
	kfree_skb(skb);
	kfree(a);
	return err;
}
