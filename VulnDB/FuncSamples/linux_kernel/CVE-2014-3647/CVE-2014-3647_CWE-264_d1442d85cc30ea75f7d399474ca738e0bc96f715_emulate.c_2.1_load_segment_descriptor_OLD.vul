static int load_segment_descriptor(struct x86_emulate_ctxt *ctxt,
				   u16 selector, int seg)
{
	u8 cpl = ctxt->ops->cpl(ctxt);
	return __load_segment_descriptor(ctxt, selector, seg, cpl, false);
}
