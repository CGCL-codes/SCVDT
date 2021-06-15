static int em_call_far(struct x86_emulate_ctxt *ctxt)
{
	u16 sel, old_cs;
	ulong old_eip;
	int rc;

	old_cs = get_segment_selector(ctxt, VCPU_SREG_CS);
	old_eip = ctxt->_eip;

	memcpy(&sel, ctxt->src.valptr + ctxt->op_bytes, 2);
	if (load_segment_descriptor(ctxt, sel, VCPU_SREG_CS))
		return X86EMUL_CONTINUE;

	ctxt->_eip = 0;
	memcpy(&ctxt->_eip, ctxt->src.valptr, ctxt->op_bytes);

	ctxt->src.val = old_cs;
	rc = em_push(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	ctxt->src.val = old_eip;
	return em_push(ctxt);
}
