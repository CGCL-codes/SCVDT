static bool ldm_frag_add (const u8 *data, int size, struct list_head *frags)
{
	struct frag *f;
	struct list_head *item;
	int rec, num, group;

	BUG_ON (!data || !frags);

	if (size < 2 * VBLK_SIZE_HEAD) {
		ldm_error("Value of size is to small.");
		return false;
	}

	group = get_unaligned_be32(data + 0x08);
	rec   = get_unaligned_be16(data + 0x0C);
	num   = get_unaligned_be16(data + 0x0E);
	if ((num < 1) || (num > 4)) {
		ldm_error ("A VBLK claims to have %d parts.", num);
		return false;
	}
	if (rec >= num) {
		ldm_error("REC value (%d) exceeds NUM value (%d)", rec, num);
		return false;
	}

	list_for_each (item, frags) {
		f = list_entry (item, struct frag, list);
		if (f->group == group)
			goto found;
	}

	f = kmalloc (sizeof (*f) + size*num, GFP_KERNEL);
	if (!f) {
		ldm_crit ("Out of memory.");
		return false;
	}

	f->group = group;
	f->num   = num;
	f->rec   = rec;
	f->map   = 0xFF << num;

	list_add_tail (&f->list, frags);
found:
	if (f->map & (1 << rec)) {
		ldm_error ("Duplicate VBLK, part %d.", rec);
		f->map &= 0x7F;			/* Mark the group as broken */
		return false;
	}

	f->map |= (1 << rec);

	data += VBLK_SIZE_HEAD;
	size -= VBLK_SIZE_HEAD;

	memcpy (f->data+rec*(size-VBLK_SIZE_HEAD)+VBLK_SIZE_HEAD, data, size);

	return true;
}
