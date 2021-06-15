static int em_jmp_far(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned short sel, old_sel;
	struct desc_struct old_desc, new_desc;
	const struct x86_emulate_ops *ops = ctxt->ops;
	u8 cpl = ctxt->ops->cpl(ctxt);

	/* Assignment of RIP may only fail in 64-bit mode */
	if (ctxt->mode == X86EMUL_MODE_PROT64)
		ops->get_segment(ctxt, &old_sel, &old_desc, NULL,
				 VCPU_SREG_CS);

	memcpy(&sel, ctxt->src.valptr + ctxt->op_bytes, 2);

	rc = __load_segment_descriptor(ctxt, sel, VCPU_SREG_CS, cpl, false,
				       &new_desc);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = assign_eip_far(ctxt, ctxt->src.val, new_desc.l);
	if (rc != X86EMUL_CONTINUE) {
		WARN_ON(!ctxt->mode != X86EMUL_MODE_PROT64);
		/* assigning eip failed; restore the old cs */
		ops->set_segment(ctxt, old_sel, &old_desc, 0, VCPU_SREG_CS);
		return rc;
	}
	return rc;
}
