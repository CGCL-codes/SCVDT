static int em_ret(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned long eip;

	rc = emulate_pop(ctxt, &eip, ctxt->op_bytes);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	return assign_eip_near(ctxt, eip);
}
