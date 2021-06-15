static int em_loop(struct x86_emulate_ctxt *ctxt)
{
	int rc = X86EMUL_CONTINUE;

	register_address_increment(ctxt, reg_rmw(ctxt, VCPU_REGS_RCX), -1);
	if ((address_mask(ctxt, reg_read(ctxt, VCPU_REGS_RCX)) != 0) &&
	    (ctxt->b == 0xe2 || test_cc(ctxt->b ^ 0x5, ctxt->eflags)))
		rc = jmp_rel(ctxt, ctxt->src.val);

	return rc;
}
