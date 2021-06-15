static int em_jmp_far(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned short sel;

	memcpy(&sel, ctxt->src.valptr + ctxt->op_bytes, 2);

	rc = load_segment_descriptor(ctxt, sel, VCPU_SREG_CS);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	ctxt->_eip = 0;
	memcpy(&ctxt->_eip, ctxt->src.valptr, ctxt->op_bytes);
	return X86EMUL_CONTINUE;
}
