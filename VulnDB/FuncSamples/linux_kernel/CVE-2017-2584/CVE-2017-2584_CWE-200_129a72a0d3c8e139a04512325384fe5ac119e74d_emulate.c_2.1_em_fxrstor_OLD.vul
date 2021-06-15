static int em_fxrstor(struct x86_emulate_ctxt *ctxt)
{
	struct fxregs_state fx_state;
	int rc;

	rc = check_fxsr(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = segmented_read(ctxt, ctxt->memop.addr.mem, &fx_state, 512);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (fx_state.mxcsr >> 16)
		return emulate_gp(ctxt, 0);

	ctxt->ops->get_fpu(ctxt);

	if (ctxt->mode < X86EMUL_MODE_PROT64)
		rc = fxrstor_fixup(ctxt, &fx_state);

	if (rc == X86EMUL_CONTINUE)
		rc = asm_safe("fxrstor %[fx]", : [fx] "m"(fx_state));

	ctxt->ops->put_fpu(ctxt);

	return rc;
}
