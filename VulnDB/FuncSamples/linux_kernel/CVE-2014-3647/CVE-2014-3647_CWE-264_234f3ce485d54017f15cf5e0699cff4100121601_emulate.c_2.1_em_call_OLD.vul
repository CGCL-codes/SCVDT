static int em_call(struct x86_emulate_ctxt *ctxt)
{
	long rel = ctxt->src.val;

	ctxt->src.val = (unsigned long)ctxt->_eip;
	jmp_rel(ctxt, rel);
	return em_push(ctxt);
}
