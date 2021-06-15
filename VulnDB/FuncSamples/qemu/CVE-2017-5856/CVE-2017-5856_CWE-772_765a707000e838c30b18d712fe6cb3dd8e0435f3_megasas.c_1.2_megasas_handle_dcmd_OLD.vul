static int megasas_handle_dcmd(MegasasState *s, MegasasCmd *cmd)
{
    int opcode, len;
    int retval = 0;
    const struct dcmd_cmd_tbl_t *cmdptr = dcmd_cmd_tbl;

    opcode = le32_to_cpu(cmd->frame->dcmd.opcode);
    trace_megasas_handle_dcmd(cmd->index, opcode);
    len = megasas_map_dcmd(s, cmd);
    if (len < 0) {
        return MFI_STAT_MEMORY_NOT_AVAILABLE;
    }
    while (cmdptr->opcode != -1 && cmdptr->opcode != opcode) {
        cmdptr++;
    }
    if (cmdptr->opcode == -1) {
        trace_megasas_dcmd_unhandled(cmd->index, opcode, len);
        retval = megasas_dcmd_dummy(s, cmd);
    } else {
        trace_megasas_dcmd_enter(cmd->index, cmdptr->desc, len);
        retval = cmdptr->func(s, cmd);
    }
    if (retval != MFI_STAT_INVALID_STATUS) {
        megasas_finish_dcmd(cmd, len);
    }
    return retval;
}
