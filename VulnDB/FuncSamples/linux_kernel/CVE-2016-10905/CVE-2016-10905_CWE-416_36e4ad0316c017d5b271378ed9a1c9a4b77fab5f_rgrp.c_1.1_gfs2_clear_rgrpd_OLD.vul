void gfs2_clear_rgrpd(struct gfs2_sbd *sdp)
{
	struct rb_node *n;
	struct gfs2_rgrpd *rgd;
	struct gfs2_glock *gl;

	while ((n = rb_first(&sdp->sd_rindex_tree))) {
		rgd = rb_entry(n, struct gfs2_rgrpd, rd_node);
		gl = rgd->rd_gl;

		rb_erase(n, &sdp->sd_rindex_tree);

		if (gl) {
			spin_lock(&gl->gl_lockref.lock);
			gl->gl_object = NULL;
			spin_unlock(&gl->gl_lockref.lock);
			gfs2_glock_add_to_lru(gl);
			gfs2_glock_put(gl);
		}

		gfs2_free_clones(rgd);
		kfree(rgd->rd_bits);
		return_all_reservations(rgd);
		kmem_cache_free(gfs2_rgrpd_cachep, rgd);
	}
}
