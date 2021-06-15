struct tc_action *tcf_action_init_1(struct net *net, struct nlattr *nla,
				    struct nlattr *est, char *name, int ovr,
				    int bind)
{
	struct tc_action *a;
	struct tc_action_ops *a_o;
	char act_name[IFNAMSIZ];
	struct nlattr *tb[TCA_ACT_MAX + 1];
	struct nlattr *kind;
	int err;

	if (name == NULL) {
		err = nla_parse_nested(tb, TCA_ACT_MAX, nla, NULL);
		if (err < 0)
			goto err_out;
		err = -EINVAL;
		kind = tb[TCA_ACT_KIND];
		if (kind == NULL)
			goto err_out;
		if (nla_strlcpy(act_name, kind, IFNAMSIZ) >= IFNAMSIZ)
			goto err_out;
	} else {
		err = -EINVAL;
		if (strlcpy(act_name, name, IFNAMSIZ) >= IFNAMSIZ)
			goto err_out;
	}

	a_o = tc_lookup_action_n(act_name);
	if (a_o == NULL) {
#ifdef CONFIG_MODULES
		rtnl_unlock();
		request_module("act_%s", act_name);
		rtnl_lock();

		a_o = tc_lookup_action_n(act_name);

		/* We dropped the RTNL semaphore in order to
		 * perform the module load.  So, even if we
		 * succeeded in loading the module we have to
		 * tell the caller to replay the request.  We
		 * indicate this using -EAGAIN.
		 */
		if (a_o != NULL) {
			err = -EAGAIN;
			goto err_mod;
		}
#endif
		err = -ENOENT;
		goto err_out;
	}

	/* backward compatibility for policer */
	if (name == NULL)
		err = a_o->init(net, tb[TCA_ACT_OPTIONS], est, &a, ovr, bind);
	else
		err = a_o->init(net, nla, est, &a, ovr, bind);
	if (err < 0)
		goto err_mod;

	if (tb[TCA_ACT_COOKIE]) {
		int cklen = nla_len(tb[TCA_ACT_COOKIE]);

		if (cklen > TC_COOKIE_MAX_SIZE) {
			err = -EINVAL;
			tcf_hash_release(a, bind);
			goto err_mod;
		}

		if (nla_memdup_cookie(a, tb) < 0) {
			err = -ENOMEM;
			tcf_hash_release(a, bind);
			goto err_mod;
		}
	}

	/* module count goes up only when brand new policy is created
	 * if it exists and is only bound to in a_o->init() then
	 * ACT_P_CREATED is not returned (a zero is).
	 */
	if (err != ACT_P_CREATED)
		module_put(a_o->owner);

	return a;

err_mod:
	module_put(a_o->owner);
err_out:
	return ERR_PTR(err);
}
