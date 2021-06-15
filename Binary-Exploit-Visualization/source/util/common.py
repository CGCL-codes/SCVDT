import claripy

def BV2Int(bv):
    if isinstance(bv, int):
        return bv
    assert(bv.concrete)
    return bv.args[0]

def state_timestamp(state):
    return str(len(state.history.bbl_addrs.hardcopy))

def set_state_options(state):
    state.options.discard("UNICORN")
    state.options.discard("COPY_STATES")
    # state.options.discard("OPTIMIZE_IR")
    # state.options.discard("TRACK_MEMORY_MAPPING")
    # state.options.discard("REGION_MAPPING")
    # state.options.discard("TRACK_CONSTRAINTS")
    # if doesn't add this option, the path will fork
    state.options.add("SUPPORT_FLOATING_POINT")
    state.options.add("USE_SYSTEM_TIMES")
    state.options.add("CONCRETIZE")
    return state

def delete_state_bbl_addrs_length(state):
    state.history.recent_bbl_addrs.pop()
    state.history.recent_block_count = 0