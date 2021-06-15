import angr.state_plugins.heap
from arena import *
from parse_helpers import *
from util.info_print import   printable_memory, printable_callstack
from analysis import register_ana
from util.common import *
import logger

"""
TODO: move this part to doc
Heap analysis, focus on alloc, free and read/write on heap.

To detect overflow:
Backward overflow:
    A write with size exceeding the size of chunk.
    We need write bp definitly, so set a bp on malloc's return address, we can track all operaion
    on that chunk.
    Remove the bp after the chunk is freed.
Forward overflow:
    A write's start address is before the begin of the chunk.(Just care about metadata of 
    chunk structure. Even with source code, we cannot define if a write writes to unexpected place)
    Set write bp on chunk's metadata.
    2 conditions to consider:
        1. allocated chunk: set write bp on its matadata, delete the bp on free
        2. free chunk: how to know where the chunk is ???
            2.1 after free, set bp on all chunks tracked by arena.
            2.2 when alloced, remove the bp
        3. heap operation itself write to free chunks, identify them by call stack?

Fake chunk:
Chunks to be free must be malloc before, so track malloc to identify fake chunks.

UAF:
For simple double free it is easy. TODO: any other case?
"""


def bp_overflow(report_logger, start_addr, size, callback = None):
    def write_bp(state):
        target_addr = state.inspect.mem_write_address
        # target_size = state.inspect.mem_write_length
        if type(target_addr) != int:
            target_addr = target_addr.args[0]
        # if type(target_size) != int:
        #     target_size = target_size.args[0]
        target_size = state.inspect.mem_write_expr.size() // state.arch.byte_width

        
        if (target_addr >= start_addr + size) \
            or (start_addr >= target_addr + target_size):
            return

        if (target_addr + target_size > start_addr + size):
            overflow_len = target_addr + target_size - (start_addr + size)
            # mem_wriet_expr = state.inspect.mem_write_expr
            mem_wriet_expr = state.memory.load(target_addr, target_size, endness = 'Iend_BE')
            overflow_content = mem_wriet_expr[overflow_len*8 - 1:0]
            memory = printable_memory(state, min(start_addr, target_addr), max(size,target_size)\
                ,warn_pos = start_addr+size, warn_size  = overflow_len, info_pos = target_addr\
                    ,info_size = target_size)
            message = "Found chunk overflow at %s." % hex(start_addr)
            report_logger.warn(message, type='heap_overflow', start_addr = start_addr, size = size, target_addr = target_addr, \
                               target_size = target_size, overflow_len = overflow_len, overflow_content = overflow_content, \
                               memory = memory, state_timestamp = state_timestamp(state))
        return
    return write_bp


def bp_redzone(report_logger, bp_start_addr, bp_size, callback = None,  allow_heap_ops_size = 0, mtype = 'redzone'):
    def write_bp(state):
        nonlocal bp_start_addr, bp_size
        start_addr = bp_start_addr
        size = bp_size
        target_addr = state.inspect.mem_write_address
        # target_size = state.inspect.mem_write_length

        if type(target_addr) != int:
            target_addr = target_addr.args[0]
        # if type(target_size) != int:
        #     target_size = target_size.args[0]
        target_size = state.inspect.mem_write_expr.size() // state.arch.byte_width

        # it does not overlap
        if (target_addr >= start_addr + size) \
            or (start_addr >= target_addr + target_size):
            return
        info_pos = target_addr
        info_size = target_size
        # info_pos 是内存写操作的地址
        # info_size 是内存写入操作的大小

        # true analysis starts from here
        # XXX: at present we extract the write content within the redzone, should we display whole
        # write content?
        if target_addr < start_addr:
            offset = start_addr - target_addr
            # target_size : mem_write's size
            # size : bp's size
            write_size = min(target_size - offset, size)
            target_addr = start_addr
        else:
            offset = target_addr - start_addr
            write_size = min(target_size, size - offset)
            offset = 0
        # target_addr 是重叠部分的最低地址
        # write_size 是
        assert(write_size)
        # figure out if this write comes from heap operations
        if write_size <  allow_heap_ops_size:
            bt = printable_callstack(state)
            if  'alloc' in bt or 'free'  in bt:
                #print(frame)
                return
            
        # write_expr = state.inspect.mem_write_expr
        write_expr = state.memory.load(info_pos, info_size, endness = 'Iend_BE')
        write_expr_inspect = state.inspect.mem_write_expr
        # print(write_expr)
        # print(write_expr_inspect)
        write_expr = write_expr[(target_size-offset)*8 - 1: (target_size-offset-write_size)*8]
        # print("%s %s" % ((target_size-offset)*8 - 1, (target_size-offset-write_size)*8))

        # if size > 0x40:
        start_addr = ((target_addr>>4)<<4) - 0x10
        size = ((size>>4)<<4) + 0x10
        # size = ((write_size>>4)<<4) + 0x10

        memory = printable_memory(state, start_addr \
            , size, warn_pos = target_addr,\
                 warn_size  = write_size, info_pos = info_pos, info_size = info_size)

        backtrace = printable_callstack(state)

        arena = Arena(state)
        # if arena.arena is not None:
            # print("=========after red:\n"+arena.output_all_bins())
            # arena.do_check()
            # pass

        tcache = Tcache(state, state.project.heap_analysis.heapbase)
        # if tcache.tcache is not None:
            # print(tcache.output_tcache_bins())
            # tcache.do_check()
            # pass

        message = "Redzone(%s) at %s overwritten." %(mtype, hex(bp_start_addr))
        report_logger.warn(message, type="redzone_write",mtype = mtype, \
                           write_addr = info_pos, write_size = info_size, start_addr = bp_start_addr, \
                           covered_addr = target_addr, covered_size = write_size, covered_expr = write_expr.args[0], \
                           backtrace = backtrace, memory = memory, \
                           state_timestamp = state_timestamp(state), \
                           malloc_state = "None" if arena.arena is None else arena.output_all_bins(), \
                           tcache = "None" if tcache.tcache is None else tcache.output_tcache_bins())
        return
    return write_bp


def ret_cb(ana, **kwargs):
    def ret_callback(state):
        if not state.project.heap_analysis.is_heap_init:
            return
        heapbase = state.project.heap_analysis.heapbase
        rax = state.regs.rax
        assert (rax.concrete)
        rax = rax.args[0]
        print("rax %s" % hex(rax))
        if (rax >> 12) != (heapbase >> 12):
            return
        if rax <= heapbase:
            return
        size = state.memory.load(rax - 8, 8, endness='Iend_LE')
        assert (size.concrete)
        size = size.args[0]
        size = (size >> 4) << 4
        tcache_sizes = {0x250, 0x290}
        if size not in tcache_sizes:
            return
        state.project.heap_analysis.is_tcache_init = True
        state.project.heap_analysis.tcache_address = rax
        print("tcache addr %s" % hex(rax))
        state.inspect.remove_breakpoint(event_type="return", \
                                        bp = state.project.heap_analysis.tcache_init_bp)
        # delete calloc‘s hook function
        # state.project.heap_analysis.disable_hook("calloc")
        state.project.heap_analysis.tcache_init_bp = None
        return

    return ret_callback

def set_tcache_bp(state):
    if state.project.heap_analysis.tcache_enable == True:
        if state.project.heap_analysis.is_tcache_init == False and \
                state.project.heap_analysis.tcache_init_bp is None:
            tcache_ret_cb = ret_cb(state.project.heap_analysis)
            state.project.heap_analysis.tcache_init_bp = \
                state.inspect.b("return", when = angr.BP_AFTER, action = tcache_ret_cb)
            print("set tcache return bp")


def find_chunks(chks, addr):
    for chk in chks:
        if addr == chk[0]:
            return True
    return False


def _malloc_hook(state):
    """
    malloc hook.
    Get size passed to malloc, and set a hook on caller's return address to get malloc's 
    return value.
    After getting the return value, unhook the return address.
    """
    # get return address and arg
    size = state.regs.rdi
    assert(size.concrete)
    size = size.args[0]
    origin_size = size
    size = ((size>>4)<<4) + 0x10
    if size < 0x20:
        size = 0x20

    rsp = state.regs.rsp
    assert(rsp.concrete)
    # stack frame haven't been created, so return address is in rsp
    ret_addr = state.memory.load(rsp, 8, endness = 'Iend_LE')
    assert(ret_addr.concrete)
    ret_addr = ret_addr.args[0]
    #print(hex(ret_addr))
    # To get tcache address if tcache mechanism is enabled
    set_tcache_bp(state)

    # hook add the bbl_addrs's length, please delete it
    delete_state_bbl_addrs_length(state)

    def _malloc_callback(state):
        # rax contains return address of malloc
        state.project.unhook(ret_addr)
        rax = state.regs.rax
        assert(rax.concrete)
        rax = rax.args[0]

        delete_state_bbl_addrs_length(state)

        arena = Arena(state, rax)
        # if arena.arena is not None:
            # print("=========after malloc:\n"+arena.output_all_bins())
            # arena.do_check()
            # pass

        tcache = Tcache(state, state.project.heap_analysis.heapbase)
        # if tcache.tcache is not None:
            # print(tcache.output_tcache_bins())
            # tcache.do_check()
            # pass

        true_size = state.memory.load(rax-8, 8, endness = 'Iend_LE')
        assert (true_size.concrete)
        true_size = true_size.args[0]
        true_size = (true_size >> 4) << 4

        message = "Memory allocate: malloc(%s) => %s" % (hex(true_size), hex(rax))
        state.project.report_logger.info(message, size = true_size, addr = rax, type = "malloc", \
                                         state_timestamp = state_timestamp(state), \
                                         origin_size = origin_size, \
                                         malloc_state="None" if arena.arena is None else arena.output_all_bins(), \
                                         tcache="None" if tcache.tcache is None else tcache.output_tcache_bins())
        # TODO: check if return addr is sane. 
        symbol = state.project.symbol_resolve.reverse_resolve(rax) # dirty but easy
        if symbol:
            # print(symbol)
            message = "Chunk allocated at (%s <- %s%+d)not in heap."% (hex(rax), symbol[0], symbol[1])
            backtrace = printable_callstack(state)
            state.project.report_logger.warn(message, symbol = symbol[0], offset = symbol[1], backtrace = backtrace, \
                                             type = 'alloc_warn', state_timestamp = state_timestamp(state))

        if rax <= state.project.heap_analysis.stack_area["end"] and \
                rax >= state.project.heap_analysis.stack_area["start"]:
            message = "Chunk allocated at (%s) in stack." % hex(rax)
            backtrace = printable_callstack(state)
            state.project.report_logger.warn(message, backtrace=backtrace,
                                           type='alloc_warn', state_timestamp=state_timestamp(state))

        state.project.heap_analysis.add_chunk(rax, true_size, state)

        chks = arena.get_all_chunks()
        if tcache.tcache is not None:
            chks += tcache.get_all_chunks()

        free_bps = state.project.heap_analysis.free_bps
        if rax - 0x10 in free_bps and find_chunks(chks, rax-0x10) is False:
            state.inspect.remove_breakpoint(event_type = 'mem_write', bp = free_bps[rax-0x10])
            state.project.heap_analysis.free_bps.pop(rax-0x10)
        if rax in free_bps and find_chunks(chks, rax) is False:
            state.inspect.remove_breakpoint(event_type = 'mem_write', bp = free_bps[rax])
            state.project.heap_analysis.free_bps.pop(rax)
    
        bp_content = state.inspect.b("mem_write", when=angr.BP_AFTER, action = \
            bp_overflow(state.project.report_logger, rax, origin_size))
        bp_metadata = state.inspect.b("mem_write", when=angr.BP_AFTER, action = \
            # bp_redzone(state.project.report_logger, rax-0x10, 0x10, allow_heap_ops_size = 0x10, mtype = 'chunk header'))
            bp_redzone(state.project.report_logger, rax - 0x8, 0x8, allow_heap_ops_size=0x10, mtype='chunk header'))

        inuse_bps = state.project.heap_analysis.inuse_bps
        if rax in inuse_bps:
            state.inspect.remove_breakpoint(event_type= 'mem_write', bp=inuse_bps[rax])
        if rax - 0x10 in inuse_bps:
            state.inspect.remove_breakpoint(event_type='mem_write', bp=inuse_bps[rax-0x10])
        state.project.heap_analysis.inuse_bps[rax] = bp_content
        state.project.heap_analysis.inuse_bps[rax - 0x10] = bp_metadata



    #assert(not state.project.is_hooked(ret_addr))
    if state.project.is_hooked(ret_addr):
        state.project.unhook(ret_addr)
    state.project.hook(ret_addr, _malloc_callback)


def _realloc_hook(state):
    addr = state.regs.rdi
    assert (addr.concrete)
    addr = addr.args[0]

    size = state.regs.rsi
    assert (size.concrete)
    size = size.args[0]
    origin_size = size

    if addr != 0:
        # since the chunk is freed, remove write bps
        bps = state.project.heap_analysis.inuse_bps
        if addr in bps:
            state.inspect.remove_breakpoint(event_type='mem_write', bp=bps[addr])
            bps.pop(addr)
        if addr - 0x10 in bps:
            state.inspect.remove_breakpoint(event_type='mem_write', bp=bps[addr - 0x10])
            bps.pop(addr - 0x10)

        free_ptr_size = state.memory.load(addr - 8, 8, endness='Iend_LE')
        assert (free_ptr_size.concrete)
        free_ptr_size = free_ptr_size.args[0]
        free_ptr_size = (free_ptr_size >> 4) << 4

    for free_addr, bp in state.project.heap_analysis.free_bps.items():
        # print(state.inspect._breakpoints)
        state.inspect.remove_breakpoint(event_type='mem_write', bp=bp)
    state.project.heap_analysis.free_bps = {}

    rsp = state.regs.rsp
    assert (rsp.concrete)
    # stack frame haven't been created, so return address is in rsp
    ret_addr = state.memory.load(rsp, 8, endness='Iend_LE')
    assert (ret_addr.concrete)
    ret_addr = ret_addr.args[0]

    # To get tcache address if tcache mechanism is enabled
    set_tcache_bp(state)

    # hook add the bbl_addrs's length, please delete it
    delete_state_bbl_addrs_length(state)


    def _realloc_malloc_callback(state):
        # rax contains return address of malloc
        state.project.unhook(ret_addr)
        rax = state.regs.rax
        assert (rax.concrete)
        rax = rax.args[0]

        delete_state_bbl_addrs_length(state)

        arena = Arena(state, rax)

        tcache = Tcache(state, state.project.heap_analysis.heapbase)

        true_size = state.memory.load(rax - 8, 8, endness='Iend_LE')
        assert (true_size.concrete)
        true_size = true_size.args[0]
        true_size = (true_size >> 4) << 4

        message = "Memory allocate: realloc(%s, %s) => %s" % (hex(addr), hex(true_size), hex(rax))
        state.project.report_logger.info(message, size=true_size, addr=rax, type="malloc", \
                                         state_timestamp=state_timestamp(state), \
                                         origin_size=origin_size, \
                                         malloc_state="None" if arena.arena is None else arena.output_all_bins(), \
                                         tcache="None" if tcache.tcache is None else tcache.output_tcache_bins())
        # TODO: check if return addr is sane.
        symbol = state.project.symbol_resolve.reverse_resolve(rax)  # dirty but easy
        if symbol:
            # print(symbol)
            message = "Chunk allocated at (%s <- %s%+d)not in heap." % (hex(rax), symbol[0], symbol[1])
            backtrace = printable_callstack(state)
            state.project.report_logger.warn(message, symbol=symbol[0], offset=symbol[1], backtrace=backtrace, \
                                             type='alloc_warn', state_timestamp=state_timestamp(state))

        if rax <= state.project.heap_analysis.stack_area["end"] and \
                rax >= state.project.heap_analysis.stack_area["start"]:
            message = "Chunk allocated at (%s) in stack." % hex(rax)
            backtrace = printable_callstack(state)
            state.project.report_logger.warn(message, backtrace=backtrace,
                                             type='alloc_warn', state_timestamp=state_timestamp(state))

        if addr != 0 and addr != rax:
            state.project.heap_analysis.del_chunk(addr, free_ptr_size, state)
        state.project.heap_analysis.add_chunk(rax, true_size, state, type="realloc")

        chks = arena.get_all_chunks()
        if tcache.tcache is not None:
            chks += tcache.get_all_chunks()

        # free_bps = state.project.heap_analysis.free_bps
        # if rax - 0x10 in free_bps and find_chunks(chks, rax - 0x10) is False:
        #     state.inspect.remove_breakpoint(event_type='mem_write', bp=free_bps[rax - 0x10])
        #     state.project.heap_analysis.free_bps.pop(rax - 0x10)
        # if rax in free_bps and find_chunks(chks, rax) is False:
        #     state.inspect.remove_breakpoint(event_type='mem_write', bp=free_bps[rax])
        #     state.project.heap_analysis.free_bps.pop(rax)

        bp_content = state.inspect.b("mem_write", when=angr.BP_AFTER, action= \
            bp_overflow(state.project.report_logger, rax, origin_size))
        bp_metadata = state.inspect.b("mem_write", when=angr.BP_AFTER, action= \
            # bp_redzone(state.project.report_logger, rax-0x10, 0x10, allow_heap_ops_size = 0x10, mtype = 'chunk header'))
            bp_redzone(state.project.report_logger, rax - 0x8, 0x8, allow_heap_ops_size=0x10, mtype='chunk header'))

        inuse_bps = state.project.heap_analysis.inuse_bps
        if rax in inuse_bps:
            state.inspect.remove_breakpoint(event_type='mem_write', bp=inuse_bps[rax])
        if rax - 0x10 in inuse_bps:
            state.inspect.remove_breakpoint(event_type='mem_write', bp=inuse_bps[rax - 0x10])
        state.project.heap_analysis.inuse_bps[rax] = bp_content
        state.project.heap_analysis.inuse_bps[rax - 0x10] = bp_metadata

        for chk in chks:
            chk_size = (chk[1] >> 4) << 4
            bp = state.inspect.b('mem_write', when=angr.BP_AFTER, action= \
                bp_redzone(state.project.report_logger, chk[0] + 0x8, chk_size - 0x8, allow_heap_ops_size=0x20,
                           mtype="freed chunk"))
            state.project.heap_analysis.free_bps[chk[0]] = bp




    def _realloc_free_callback(state):
        state.project.heap_analysis.parse_arena(state)
        state.project.unhook(ret_addr)

        delete_state_bbl_addrs_length(state)

        arena = Arena(state, addr=addr)
        chks = arena.get_all_chunks()

        tcache = Tcache(state, addr=state.project.heap_analysis.heapbase)
        if tcache.tcache is not None:
            chks += tcache.get_all_chunks()

        message = "Memory free: realloc(%s, %s) (size: %s)" % (hex(addr), hex(size), hex(free_ptr_size))
        state.project.report_logger.info(message, addr=addr, size=free_ptr_size, type="free", \
                                         state_timestamp=state_timestamp(state), \
                                         malloc_state="None" if arena.arena is None else arena.output_all_bins(), \
                                         tcache="None" if tcache.tcache is None else tcache.output_tcache_bins())

        if addr != 0:
            state.project.heap_analysis.del_chunk(addr, free_ptr_size, state)

        if addr <= state.project.heap_analysis.stack_area["end"] and \
                addr >= state.project.heap_analysis.stack_area["start"]:
            message = "Chunk freed (%s) in stack." % hex(addr)
            backtrace = printable_callstack(state)
            state.project.report_logger.warn(message, backtrace=backtrace,
                                             type='freed_warn', state_timestamp=state_timestamp(state))

        for chk in chks:
            chk_size = (chk[1] >> 4) << 4
            bp = state.inspect.b('mem_write', when=angr.BP_AFTER, action= \
                bp_redzone(state.project.report_logger, chk[0] + 0x8, chk_size - 0x8, allow_heap_ops_size=0x20,
                           mtype="freed chunk"))
            state.project.heap_analysis.free_bps[chk[0]] = bp





    # assert(not state.project.is_hooked(ret_addr))
    if state.project.is_hooked(ret_addr):
        state.project.unhook(ret_addr)

    if size == 0 and addr != 0:
        # same with free operation
        state.project.hook(ret_addr, _realloc_free_callback)
    elif addr != 0:
        # realloc and malloc
        state.project.hook(ret_addr, _realloc_malloc_callback)


# TODO： rewrite this!!!!
def _calloc_hook(state):
    """
    Same with _malloc_hook
    """
    # get return address and arg
    count = state.regs.rdi
    assert(count.concrete)
    count = count.args[0]

    size = state.regs.rsi
    assert(size.concrete)
    size = size.args[0]

    origin_size = count * size

    # if sum_size < 0x20:
    #     size = 0x20

    rsp = state.regs.rsp
    assert (rsp.concrete)
    # stack frame haven't been created, so return address is in rsp
    ret_addr = state.memory.load(rsp, 8, endness='Iend_LE')
    assert (ret_addr.concrete)
    ret_addr = ret_addr.args[0]
    # To get tcache address if tcache mechanism is enabled
    set_tcache_bp(state)

    # hook add the bbl_addrs's length, please delete it
    delete_state_bbl_addrs_length(state)

    for free_addr, bp in state.project.heap_analysis.free_bps.items():
            #print(state.inspect._breakpoints)
        state.inspect.remove_breakpoint(event_type = 'mem_write', bp = bp)
    state.project.heap_analysis.free_bps = {}

    def _calloc_callback(state):
        # rax contains return address of calloc
        state.project.unhook(ret_addr)
        rax = state.regs.rax
        assert(rax.concrete)
        rax = rax.args[0]

        delete_state_bbl_addrs_length(state)

        arena = Arena(state, rax)
        tcache = Tcache(state, state.project.heap_analysis.heapbase)

        true_size = state.memory.load(rax - 8, 8, endness='Iend_LE')
        assert (true_size.concrete)
        true_size = true_size.args[0]
        true_size = (true_size >> 4) << 4

        message = "Memory allocate: calloc(%s) => %s" % (hex(true_size), hex(rax))
        state.project.report_logger.info(message, size=true_size, addr=rax, type="malloc", \
                                         state_timestamp=state_timestamp(state), \
                                         origin_size=origin_size, \
                                         malloc_state="None" if arena.arena is None else arena.output_all_bins(), \
                                         tcache="None" if tcache.tcache is None else tcache.output_tcache_bins())
        # TODO: check if return addr is sane.
        symbol = state.project.symbol_resolve.reverse_resolve(rax)  # dirty but easy
        if symbol:
            # print(symbol)
            message = "Chunk allocated at (%s <- %s%+d)not in heap." % (hex(rax), symbol[0], symbol[1])
            backtrace = printable_callstack(state)
            state.project.report_logger.warn(message, symbol=symbol[0], offset=symbol[1], backtrace=backtrace, \
                                             type='alloc_warn', state_timestamp=state_timestamp(state))

        if rax <= state.project.heap_analysis.stack_area["end"] and \
                rax >= state.project.heap_analysis.stack_area["start"]:
            message = "Chunk allocated at (%s) in stack." % hex(rax)
            backtrace = printable_callstack(state)
            state.project.report_logger.warn(message, backtrace=backtrace,
                                             type='alloc_warn', state_timestamp=state_timestamp(state))

        state.project.heap_analysis.add_chunk(rax, true_size, state)

        chks = arena.get_all_chunks()
        if tcache.tcache is not None:
            chks += tcache.get_all_chunks()

        # free_bps = state.project.heap_analysis.free_bps
        # if rax - 0x10 in free_bps and find_chunks(chks, rax - 0x10) is False:
        #     state.inspect.remove_breakpoint(event_type='mem_write', bp=free_bps[rax - 0x10])
        #     state.project.heap_analysis.free_bps.pop(rax - 0x10)
        # if rax in free_bps and find_chunks(chks, rax) is False:
        #     state.inspect.remove_breakpoint(event_type='mem_write', bp=free_bps[rax])
        #     state.project.heap_analysis.free_bps.pop(rax)

        bp_content = state.inspect.b("mem_write", when=angr.BP_AFTER, action= \
            bp_overflow(state.project.report_logger, rax, origin_size))
        bp_metadata = state.inspect.b("mem_write", when=angr.BP_AFTER, action= \
            # bp_redzone(state.project.report_logger, rax-0x10, 0x10, allow_heap_ops_size = 0x10, mtype = 'chunk header'))
        bp_redzone(state.project.report_logger, rax - 0x8, 0x8, allow_heap_ops_size=0x10, mtype='chunk header'))

        inuse_bps = state.project.heap_analysis.inuse_bps
        if rax in inuse_bps:
            state.inspect.remove_breakpoint(event_type='mem_write', bp=inuse_bps[rax])
        if rax - 0x10 in inuse_bps:
            state.inspect.remove_breakpoint(event_type='mem_write', bp=inuse_bps[rax - 0x10])
        state.project.heap_analysis.inuse_bps[rax] = bp_content
        state.project.heap_analysis.inuse_bps[rax - 0x10] = bp_metadata

        for chk in chks:
            chk_size = (chk[1]>>4)<<4
            bp = state.inspect.b('mem_write', when=angr.BP_AFTER, action= \
                bp_redzone(state.project.report_logger, chk[0]+0x8, chk_size-0x8, allow_heap_ops_size = 0x20, mtype = "freed chunk"))
            state.project.heap_analysis.free_bps[chk[0]] = bp


    # assert(not state.project.is_hooked(ret_addr))
    if state.project.is_hooked(ret_addr):
        state.project.unhook(ret_addr)
    state.project.hook(ret_addr, _calloc_callback)


def _free_hook(state):
    """
    free hook.
    Use chunk's metadata to decide chunk size.
    """
    # get addr and chunk_size
    addr = state.regs.rdi
    assert(addr.concrete)
    addr = addr.args[0]

    size = state.memory.load(addr-8, 8, endness = 'Iend_LE')
    assert(size.concrete)
    size = size.args[0]
    size = (size >> 4)<<4
    # print("Free called to free %s with size %s" % (hex(addr), hex(size)))

    # get info for ret callback
    # stack frame haven't been created, so return address is in rsp
    ret_addr = state.memory.load(state.regs.rsp, 8, endness = 'Iend_LE')
    ret_addr = ret_addr.args[0]

    # since the chunk is freed, remove write bps
    bps = state.project.heap_analysis.inuse_bps
    if addr in bps:
        state.inspect.remove_breakpoint(event_type = 'mem_write', bp = bps[addr])
        bps.pop(addr)
    if addr-0x10 in bps:
        state.inspect.remove_breakpoint(event_type = 'mem_write', bp = bps[addr-0x10])
        bps.pop(addr-0x10)

    for free_addr, bp in state.project.heap_analysis.free_bps.items():
            #print(state.inspect._breakpoints)
        state.inspect.remove_breakpoint(event_type = 'mem_write', bp = bp)
    state.project.heap_analysis.free_bps = {}

    delete_state_bbl_addrs_length(state)

    def _free_callback(state):
        state.project.heap_analysis.parse_arena(state)
        state.project.unhook(ret_addr)

        delete_state_bbl_addrs_length(state)

        # TEST: to be tested
        # ms, arena_addr = get_malloc_state(state, addr)
        # assert(ms)
        # fastbin_check(state, ms, arena_addr)
        # bin_check(state, ms, arena_addr)

        arena = Arena(state, addr = addr)
        # if arena.arena is not None:
            # print("=========after free:\n"+arena.output_all_bins())
            # pass
        # arena.do_check()
        chks = arena.get_all_chunks()

        tcache = Tcache(state, addr = state.project.heap_analysis.heapbase)
        if tcache.tcache is not None:
            # print(tcache.output_tcache_bins())
            chks += tcache.get_all_chunks()

        message = "Memory free: free(%s) (size: %s)" % (hex(addr), hex(size))
        state.project.report_logger.info(message, addr=addr, size=size, type="free", \
                                         state_timestamp=state_timestamp(state), \
                                         malloc_state = "None" if arena.arena is None else arena.output_all_bins(), \
                                         tcache = "None" if tcache.tcache is None else tcache.output_tcache_bins())

        if addr != 0:
            state.project.heap_analysis.del_chunk(addr, size, state)

        if addr <= state.project.heap_analysis.stack_area["end"] and \
                addr >= state.project.heap_analysis.stack_area["start"]:
            message = "Chunk freed (%s) in stack." % hex(addr)
            backtrace = printable_callstack(state)
            state.project.report_logger.warn(message, backtrace=backtrace,
                                             type='freed_warn', state_timestamp=state_timestamp(state))

        for chk in chks:
            chk_size = (chk[1]>>4)<<4
            bp = state.inspect.b('mem_write', when=angr.BP_AFTER, action= \
                bp_redzone(state.project.report_logger, chk[0]+0x8, chk_size-0x8, allow_heap_ops_size = 0x20, mtype = "freed chunk"))
            state.project.heap_analysis.free_bps[chk[0]] = bp



    #assert(not state.project.is_hooked(ret_addr))
    state.project.hook(ret_addr, _free_callback)


class heap_analysis(object):
    """
    Analyses heap operations.
    Hooks the top level api(malloc, free, etc.), get information and then use read/write
    breakpoints to do analysis.

    :ivar chunks_av:        dict of allocated chunks, indexed by address
    :ivar chunks_sv:        dict of allocated chunks, indexed by size
    :ivar abused_chunks:    list of chunks been abused, chunk sample: 
                            {"addr": 0x603000, "size":0x68, "type": abused_type}

    :ivar arenas:           list of thread_arena structs # TODO: haven't do the parse job

    :ivar bps:              read/write breakpoints. A dict indexed by bp addr.
    """
    def __init__(self, project, segments=[], ):
        self.project = project
        self.heap_segments = segments
        self.malloc_hook = _malloc_hook
        self.calloc_hook = _calloc_hook
        self.free_hook = _free_hook
        self.realloc_hook = _realloc_hook
        # self.brk_hook = _brk_hook

        self.hooked_addr = {}
        self.chunks_av = {}
        self.chunks_sv = {}
        self.abused_chunks = []
        self.chunks_mem = []
        self.arenas = []
        self.inuse_bps ={}
        self.free_bps = {}
        self.heapbase = 0
        self.init_stack()
        self.brk_address = []
        self.is_heap_init = False
        self.is_tcache_init = False
        self.tcache_enable = False
        self.tcache_address = 0
        self.tcache_init_bp = None

    def get_heapbase(self):
        if self.heapbase != 0:
            return self.heapbase
        else:
            return None

    def init_stack(self):
        if "stack" not in self.project.maps:
            print("Do not resolve stack information!")
            return
        self.stack_area = self.project.maps["stack"][0]

    # FIXME: bull shit
    def _ptr_in_chunk(self, ptr):
        for addr, size in self.chunks_av.items():
            if ptr in range(addr+0x10, addr+size-0x10):
                return addr, size
        return None

    def add_chunk(self, addr, size, state, type=None):
        """
        when a chunk is alloced, this func is called to do record and check.
        """
        # def _is_overlap_chunks(self):
        #     for chunk in range(0, self.chunks_mem):

        backtrace = printable_callstack(state)

        # do log in chunks_av
        if addr in self.chunks_av:
            # why allocated again?
            sizes = self.chunks_av[addr]
            if isinstance(sizes, list):
                sizes.append(size)
            else:
                self.chunks_av[addr] = [sizes, size]
            self.abused_chunks.append({"addr":addr, "size":size, "type":"allocated mutiple times"})
            if type != "realloc":
                self.project.report_logger.warn("Double allocated chunk", backtrace = backtrace, \
                                                addr = addr, size = size, \
                                                type = 'alloc_warn', state_timestamp = state_timestamp(state))
        else:
            self.chunks_av[addr] = size
            
        # do log in chunks_sv
        if size in self.chunks_sv:
            self.chunks_sv[size].append(addr)
        else:
            self.chunks_sv[size] = [addr]

    def del_chunk(self, addr, size, state):
        """
        when a chunk is freed, this func is called to do record and check.
        """
        # check if the chunk is allocated
        backtrace = printable_callstack(state)

        if addr in self.chunks_av:
            sizes = self.chunks_av[addr]
            # check if size matchess
            if isinstance(sizes, list):
                if size in sizes:
                    sizes.remove(size)
                    if sizes==[]:
                        self.chunks_av.pop(addr)
                else:
                    self.abused_chunks.append({"addr": addr, "size":size, "type":"freed with modified size"})
                    self.project.report_logger.warn("Chunk freed with modified size", backtrace = backtrace, addr = addr, \
                                                    size = size, type='free_warn', state_timestamp = state_timestamp(state))
            # target chunk doesn't been allocated more than one time,
            # so sizes is an int
            elif size == sizes:
                self.chunks_av.pop(addr)
            else:
                self.chunks_av.pop(addr)
                self.abused_chunks.append({"addr": addr, "size": size, "type": "freed with modified size"})
                self.project.report_logger.warn("Chunk freed with modified size", backtrace=backtrace, addr=addr, \
                                                size=size, type='free_warn', state_timestamp=state_timestamp(state))
            # do log in chunks_sv
            if size in self.chunks_sv:
                if addr in self.chunks_sv[size]:
                    self.chunks_sv[size].remove(addr)
        else:
            # this chunk is not allocated by c/m/relloc
            self.abused_chunks.append({"addr":addr, "size": size, "type":"chunk not allocated is freed"})
            self.project.report_logger.warn("Unallocated chunk is freed", backtrace = backtrace, addr = addr, size = size, \
                                            type = 'free_warn', state_timestamp = state_timestamp(state))

    
    def enable_hook(self, state):
        # hook heap api, save address to hooked_addr
        self.hooked_addr["malloc"] = self.project.hook_symbol("malloc", self.malloc_hook)
        self.hooked_addr["free"] = self.project.hook_symbol("free", self.free_hook)

        # calloc still in work
        self.hooked_addr["calloc"] = self.project.hook_symbol("calloc", self.calloc_hook)
        self.hooked_addr["realloc"] = self.project.hook_symbol("realloc", self.realloc_hook)

    def disable_hook(self, hook_symbol=None):
        # clean hooks by saved addr
        if hook_symbol is not None:
            if hook_symbol in self.hooked_addr.keys():
                self.project.unhook(self.hooked_addr[hook_symbol])
                del self.hooked_addr[hook_symbol]
            return
        for i in self.hooked_addr:
            self.project.unhook(self.hooked_addr[i])
        self.hooked_addr = {}
        return

    def set_tcache_enable_condition(self):
        """
        Judge whether tcache is enabled
        """
        if version_compare(self.project.lib_version, "2.26") >= 0:
            self.tcache_enable = True
        else:
            self.tcache_enable = False

    def parse_arena(self, state):
        pass

    def clear(self):
        self.disable_hook()
        self.hooked_addr = {}
        self.chunks_av = {}
        self.chunks_sv = {}
        self.abused_chunks = []
        self.arenas = []
        self.inuse_bps = {}
        self.free_bps = {}

    def do_analysis(self):
        """
        Do the job.
        """

        self.clear()
        self.project.report_logger = logger.get_logger(__name__)

        import time
        time_start = time.time()

        self.project.report_logger.info("Heap analysis started.", type='tips')
        self.set_tcache_enable_condition()
        state = self.project.get_entry_state()
        self.enable_hook(state)
        #state.options.discard("UNICORN")
        simgr = self.project.get_simgr(state)
        simgr.active[0] = set_state_options(simgr.active[0])

        simgr.run()
        # self.disable_hook()
        self.clear()

        time_end = time.time()
        res = "heap time cost: %s s" % (time_end - time_start)
        with open("heap.time", "w") as f:
            f.write(res)
            f.close()

        self.project.report_logger.info("Heap analysis done.", type='tips')
        
register_ana('heap_analysis', heap_analysis)

