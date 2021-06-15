int xfrm_migrate(const struct xfrm_selector *sel, u8 dir, u8 type,
		 struct xfrm_migrate *m, int num_migrate,
		 struct xfrm_kmaddress *k, struct net *net,
		 struct xfrm_encap_tmpl *encap)
{
	int i, err, nx_cur = 0, nx_new = 0;
	struct xfrm_policy *pol = NULL;
	struct xfrm_state *x, *xc;
	struct xfrm_state *x_cur[XFRM_MAX_DEPTH];
	struct xfrm_state *x_new[XFRM_MAX_DEPTH];
	struct xfrm_migrate *mp;

	/* Stage 0 - sanity checks */
	if ((err = xfrm_migrate_check(m, num_migrate)) < 0)
		goto out;

	if (dir >= XFRM_POLICY_MAX) {
		err = -EINVAL;
		goto out;
	}

	/* Stage 1 - find policy */
	if ((pol = xfrm_migrate_policy_find(sel, dir, type, net)) == NULL) {
		err = -ENOENT;
		goto out;
	}

	/* Stage 2 - find and update state(s) */
	for (i = 0, mp = m; i < num_migrate; i++, mp++) {
		if ((x = xfrm_migrate_state_find(mp, net))) {
			x_cur[nx_cur] = x;
			nx_cur++;
			xc = xfrm_state_migrate(x, mp, encap);
			if (xc) {
				x_new[nx_new] = xc;
				nx_new++;
			} else {
				err = -ENODATA;
				goto restore_state;
			}
		}
	}

	/* Stage 3 - update policy */
	if ((err = xfrm_policy_migrate(pol, m, num_migrate)) < 0)
		goto restore_state;

	/* Stage 4 - delete old state(s) */
	if (nx_cur) {
		xfrm_states_put(x_cur, nx_cur);
		xfrm_states_delete(x_cur, nx_cur);
	}

	/* Stage 5 - announce */
	km_migrate(sel, dir, type, m, num_migrate, k, encap);

	xfrm_pol_put(pol);

	return 0;
out:
	return err;

restore_state:
	if (pol)
		xfrm_pol_put(pol);
	if (nx_cur)
		xfrm_states_put(x_cur, nx_cur);
	if (nx_new)
		xfrm_states_delete(x_new, nx_new);

	return err;
}
