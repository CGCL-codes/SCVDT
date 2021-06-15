static int em_ret(struct x86_emulate_ctxt *ctxt)
{
	ctxt->dst.type = OP_REG;
	ctxt->dst.addr.reg = &ctxt->_eip;
	ctxt->dst.bytes = ctxt->op_bytes;
	return em_pop(ctxt);
}
