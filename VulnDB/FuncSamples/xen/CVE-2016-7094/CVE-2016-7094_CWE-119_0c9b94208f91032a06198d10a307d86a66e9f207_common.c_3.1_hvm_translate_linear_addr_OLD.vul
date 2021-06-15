static int hvm_translate_linear_addr(
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    struct sh_emulate_ctxt *sh_ctxt,
    unsigned long *paddr)
{
    struct segment_register *reg = hvm_get_seg_reg(seg, sh_ctxt);
    int okay;

    okay = hvm_virtual_to_linear_addr(
        seg, reg, offset, bytes, access_type, sh_ctxt->ctxt.addr_size, paddr);

    if ( !okay )
    {
        hvm_inject_hw_exception(
            (seg == x86_seg_ss) ? TRAP_stack_error : TRAP_gp_fault, 0);
        return X86EMUL_EXCEPTION;
    }

    return 0;
}
