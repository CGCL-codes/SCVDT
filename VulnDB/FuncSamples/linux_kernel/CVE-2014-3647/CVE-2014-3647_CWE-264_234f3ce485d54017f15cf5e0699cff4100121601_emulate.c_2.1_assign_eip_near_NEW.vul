static inline int assign_eip_near(struct x86_emulate_ctxt *ctxt, ulong dst)
{
	return assign_eip_far(ctxt, dst, ctxt->mode == X86EMUL_MODE_PROT64);
}
