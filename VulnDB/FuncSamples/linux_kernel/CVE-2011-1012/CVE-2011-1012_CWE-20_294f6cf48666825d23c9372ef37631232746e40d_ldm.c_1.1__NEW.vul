static bool ldm_parse_vmdb (const u8 *data, struct vmdb *vm)
{
	BUG_ON (!data || !vm);

	if (MAGIC_VMDB != get_unaligned_be32(data)) {
		ldm_crit ("Cannot find the VMDB, database may be corrupt.");
		return false;
	}

	vm->ver_major = get_unaligned_be16(data + 0x12);
	vm->ver_minor = get_unaligned_be16(data + 0x14);
	if ((vm->ver_major != 4) || (vm->ver_minor != 10)) {
		ldm_error ("Expected VMDB version %d.%d, got %d.%d. "
			"Aborting.", 4, 10, vm->ver_major, vm->ver_minor);
		return false;
	}

	vm->vblk_size     = get_unaligned_be32(data + 0x08);
	if (vm->vblk_size == 0) {
		ldm_error ("Illegal VBLK size");
		return false;
	}

	vm->vblk_offset   = get_unaligned_be32(data + 0x0C);
	vm->last_vblk_seq = get_unaligned_be32(data + 0x04);

	ldm_debug ("Parsed VMDB successfully.");
	return true;
}
