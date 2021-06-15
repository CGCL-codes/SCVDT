static int uvesafb_setcmap(struct fb_cmap *cmap, struct fb_info *info)
{
	struct uvesafb_pal_entry *entries;
	int shift = 16 - dac_width;
	int i, err = 0;

	if (info->var.bits_per_pixel == 8) {
		if (cmap->start + cmap->len > info->cmap.start +
		    info->cmap.len || cmap->start < info->cmap.start)
			return -EINVAL;

		entries = kmalloc(sizeof(*entries) * cmap->len, GFP_KERNEL);
		if (!entries)
			return -ENOMEM;

		for (i = 0; i < cmap->len; i++) {
			entries[i].red   = cmap->red[i]   >> shift;
			entries[i].green = cmap->green[i] >> shift;
			entries[i].blue  = cmap->blue[i]  >> shift;
			entries[i].pad   = 0;
		}
		err = uvesafb_setpalette(entries, cmap->len, cmap->start, info);
		kfree(entries);
	} else {
		/*
		 * For modes with bpp > 8, we only set the pseudo palette in
		 * the fb_info struct. We rely on uvesafb_setcolreg to do all
		 * sanity checking.
		 */
		for (i = 0; i < cmap->len; i++) {
			err |= uvesafb_setcolreg(cmap->start + i, cmap->red[i],
						cmap->green[i], cmap->blue[i],
						0, info);
		}
	}
	return err;
}
