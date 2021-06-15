int fb_cmap_to_user(const struct fb_cmap *from, struct fb_cmap_user *to)
{
	unsigned int tooff = 0, fromoff = 0;
	size_t size;

	if (to->start > from->start)
		fromoff = to->start - from->start;
	else
		tooff = from->start - to->start;
	if (fromoff >= from->len || tooff >= to->len)
		return -EINVAL;

	size = min_t(size_t, to->len - tooff, from->len - fromoff);
	if (size == 0)
		return -EINVAL;
	size *= sizeof(u16);

	if (copy_to_user(to->red+tooff, from->red+fromoff, size))
		return -EFAULT;
	if (copy_to_user(to->green+tooff, from->green+fromoff, size))
		return -EFAULT;
	if (copy_to_user(to->blue+tooff, from->blue+fromoff, size))
		return -EFAULT;
	if (from->transp && to->transp)
		if (copy_to_user(to->transp+tooff, from->transp+fromoff, size))
			return -EFAULT;
	return 0;
}
