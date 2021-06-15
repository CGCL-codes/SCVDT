static int fib6_add_rt2node(struct fib6_node *fn, struct rt6_info *rt,
			    struct nl_info *info)
{
	struct rt6_info *iter = NULL;
	struct rt6_info **ins;
	int replace = (info->nlh &&
		       (info->nlh->nlmsg_flags & NLM_F_REPLACE));
	int add = (!info->nlh ||
		   (info->nlh->nlmsg_flags & NLM_F_CREATE));
	int found = 0;
	bool rt_can_ecmp = rt6_qualify_for_ecmp(rt);

	ins = &fn->leaf;

	for (iter = fn->leaf; iter; iter = iter->dst.rt6_next) {
		/*
		 *	Search for duplicates
		 */

		if (iter->rt6i_metric == rt->rt6i_metric) {
			/*
			 *	Same priority level
			 */
			if (info->nlh &&
			    (info->nlh->nlmsg_flags & NLM_F_EXCL))
				return -EEXIST;
			if (replace) {
				found++;
				break;
			}

			if (iter->dst.dev == rt->dst.dev &&
			    iter->rt6i_idev == rt->rt6i_idev &&
			    ipv6_addr_equal(&iter->rt6i_gateway,
					    &rt->rt6i_gateway)) {
				if (rt->rt6i_nsiblings)
					rt->rt6i_nsiblings = 0;
				if (!(iter->rt6i_flags & RTF_EXPIRES))
					return -EEXIST;
				if (!(rt->rt6i_flags & RTF_EXPIRES))
					rt6_clean_expires(iter);
				else
					rt6_set_expires(iter, rt->dst.expires);
				return -EEXIST;
			}
			/* If we have the same destination and the same metric,
			 * but not the same gateway, then the route we try to
			 * add is sibling to this route, increment our counter
			 * of siblings, and later we will add our route to the
			 * list.
			 * Only static routes (which don't have flag
			 * RTF_EXPIRES) are used for ECMPv6.
			 *
			 * To avoid long list, we only had siblings if the
			 * route have a gateway.
			 */
			if (rt_can_ecmp &&
			    rt6_qualify_for_ecmp(iter))
				rt->rt6i_nsiblings++;
		}

		if (iter->rt6i_metric > rt->rt6i_metric)
			break;

		ins = &iter->dst.rt6_next;
	}

	/* Reset round-robin state, if necessary */
	if (ins == &fn->leaf)
		fn->rr_ptr = NULL;

	/* Link this route to others same route. */
	if (rt->rt6i_nsiblings) {
		unsigned int rt6i_nsiblings;
		struct rt6_info *sibling, *temp_sibling;

		/* Find the first route that have the same metric */
		sibling = fn->leaf;
		while (sibling) {
			if (sibling->rt6i_metric == rt->rt6i_metric &&
			    rt6_qualify_for_ecmp(sibling)) {
				list_add_tail(&rt->rt6i_siblings,
					      &sibling->rt6i_siblings);
				break;
			}
			sibling = sibling->dst.rt6_next;
		}
		/* For each sibling in the list, increment the counter of
		 * siblings. BUG() if counters does not match, list of siblings
		 * is broken!
		 */
		rt6i_nsiblings = 0;
		list_for_each_entry_safe(sibling, temp_sibling,
					 &rt->rt6i_siblings, rt6i_siblings) {
			sibling->rt6i_nsiblings++;
			BUG_ON(sibling->rt6i_nsiblings != rt->rt6i_nsiblings);
			rt6i_nsiblings++;
		}
		BUG_ON(rt6i_nsiblings != rt->rt6i_nsiblings);
	}

	/*
	 *	insert node
	 */
	if (!replace) {
		if (!add)
			pr_warn("NLM_F_CREATE should be set when creating new route\n");

add:
		rt->dst.rt6_next = iter;
		*ins = rt;
		rt->rt6i_node = fn;
		atomic_inc(&rt->rt6i_ref);
		inet6_rt_notify(RTM_NEWROUTE, rt, info);
		info->nl_net->ipv6.rt6_stats->fib_rt_entries++;

		if (!(fn->fn_flags & RTN_RTINFO)) {
			info->nl_net->ipv6.rt6_stats->fib_route_nodes++;
			fn->fn_flags |= RTN_RTINFO;
		}

	} else {
		if (!found) {
			if (add)
				goto add;
			pr_warn("NLM_F_REPLACE set, but no existing node found!\n");
			return -ENOENT;
		}
		*ins = rt;
		rt->rt6i_node = fn;
		rt->dst.rt6_next = iter->dst.rt6_next;
		atomic_inc(&rt->rt6i_ref);
		inet6_rt_notify(RTM_NEWROUTE, rt, info);
		rt6_release(iter);
		if (!(fn->fn_flags & RTN_RTINFO)) {
			info->nl_net->ipv6.rt6_stats->fib_route_nodes++;
			fn->fn_flags |= RTN_RTINFO;
		}
	}

	return 0;
}
