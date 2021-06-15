static int em_fxsave(struct x86_emulate_ctxt *ctxt)
{
	struct fxregs_state fx_state;
	size_t size;
	int rc;

	rc = check_fxsr(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	ctxt->ops->get_fpu(ctxt);

	rc = asm_safe("fxsave %[fx]", , [fx] "+m"(fx_state));

	ctxt->ops->put_fpu(ctxt);

	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->ops->get_cr(ctxt, 4) & X86_CR4_OSFXSR)
		size = offsetof(struct fxregs_state, xmm_space[8 * 16/4]);
	else
		size = offsetof(struct fxregs_state, xmm_space[0]);

	return segmented_write_std(ctxt, ctxt->memop.addr.mem, &fx_state, size);
}
