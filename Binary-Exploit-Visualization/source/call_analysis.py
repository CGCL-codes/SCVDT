import angr
from  util.info_print import stack_backtrace, printable_backtrace, fetch_str, printable_memory
from analysis import register_ana
import logger
from util.common import *
import angr.storage.memory_mixins.clouseau_mixin
import networkx
import matplotlib.pyplot as plt
"""
Set write bp on return address in stack.
TODO: get rop chain info

ROP usually calls other funcs to leak address and do other works, but the funcs called
in ROP will call other funcs recursivly, so how to judge if we should look into the calls
during ROP?

Return address changed => ret to somewhere => do a strange call X()=> 
1. call , call and call(libc func always have a deep call stack) => return to the X()'s 
caller => continue ROP attack

2. call other func, and overflow happens in the callee => other ROP operations

So there seems to be 2 situation: ROP callee just do some work, return and then continue ROP caller, 
or ROP callee(or its callee) will result in an overflow, continue attack but not return to ROP caller

Idea:
1. If overflow happens, save overflow position, so we can identify the return by the depth
2. set a track depth, track every call after step 1's return
For calls after step1's return:
3.1 If it calls other funcs, record the call if its depth haven't meet the limit we set. 
3.2 If there's a new overflow(or mismatch(unlikely)), reset track depth, get information.

There's a bug in angr's return breakpoint.
To make it work, I edited angr/engines/successors.py, lineno 211 to this:

+ if state.history.jumpkind == 'Ijk_Ret':
+                state._inspect('return', BP_AFTER)
+                return
             while True:
                 cur_sp = state.solver.max(state.regs._sp) if state.has_plugin('symbolizer') else state.regs._sp
                 if not state.solver.is_true(cur_sp > state.callstack.top.stack_ptr):
                     break
                 #state._inspect('return', BP_BEFORE, function_address=state.callstack.top.func_addr)
                 state.callstack.pop()
                 #state._inspect('return', BP_AFTER)
"""


def bp_constructor(ana, addr, origin, size = 8, callback = None):
    """
    construct a bp before given addr is written, get its origin value and modified value.
    record the addr to call_analysis.overflow_pos
    """
    def write_bp(state):
        target_addr = state.inspect.mem_write_address
        # target_size = state.inspect.mem_write_length
        write_expr = state.inspect.mem_write_expr

        if type(target_addr) != int:
            target_addr = target_addr.args[0]
        # if type(target_size) != int:
        #     target_size = target_size.args[0]
        target_size = write_expr.size() // state.arch.byte_width
        
        # make sure the write covers our addr
        if (target_addr >= addr+size):
            return
        if (target_addr + target_size <=addr):
            return

        # break on BP_AFTER, so we only need to get the value we care about
        # origin = state.memory.load(addr, 8, endness = 'Iend_LE').args[0]
        # #print(write_expr)
        bt = stack_backtrace(state)
        # backup = state.memory.load(target_addr, size)
        # state.memory.store(target_addr, write_expr, disable_actions=True, inspect = False)
        modified = state.memory.load(addr, 8, endness = 'Iend_LE').args[0]
        # ana.overflow_pos.add(addr)
        # state.memory.store(target_addr, backup, disable_actions=True, inspect = False)
        # if origin == 0x4005b4:
        #     print("found %s %s" % origin, modified)
        if origin == modified:
            return

        memory = printable_memory(state, addr-0x10, 0x30 \
                                  , warn_pos=addr, warn_size=0x8)
        message = "Return address at %s overwritten to %s" % (hex(addr), hex(modified))
        state.project.report_logger.warn(message, type='ret_addr_overwrite',stack_address = addr, \
                                         origin_return_address = origin, modified_return_address = modified, \
                                         backtrace = printable_backtrace(bt), state_timestamp = state_timestamp(state), \
                                         memory = memory)
        # def get_state_starts(state):
        #     return state.history.bbl_addrs.hardcopy[-10:]
        #
        # def generate_cfg(cfg_sequence):
        #     last_addr = cfg_sequence[0]
        #     cfg_recorded = networkx.DiGraph()
        #     for addr in cfg_sequence[1:]:
        #         cfg_recorded.add_edge(last_addr, addr)
        #         last_addr = addr
        #     networkx.draw(cfg_recorded)
        #     plt.savefig("ret_%s.png" % state_timestamp(state))
        #
        # generate_cfg(get_state_starts(state))
        #print(state.callstack)
        return
    return write_bp


def call_args_x64(state):
    regs = state.regs
    a1 = regs.rdi
    a2 = regs.rsi
    a3 = regs.rdx
    # a4 = regs.r10
    # a5 = regs.r8
    # a6 = regs.r9
    return {'rdi':a1, 'rsi':a2, 'rdx':a3}#, a4, a5, a6

def __test_filter(s, value):
    if s:
        if '__gmon_start__' in s[0]:
            s = list(s)
            s[0] = 'sub_%x'% value
            s[1] = 0
    return s

def ret_info(state):
    result = ""
    ret_src = state.history.bbl_addrs[-1]
    ret_dst = state.regs.rip.args[0]
    args = call_args_x64(state)
    dst_symbol = state.project.symbol_resolve.reverse_resolve(ret_dst, must_plus = True)
    dst_symbol = __test_filter(dst_symbol, ret_dst)
    src_symbol = state.project.symbol_resolve.reverse_resolve(ret_src, must_plus = True)
    src_symbol = __test_filter(src_symbol, ret_src)

    result += "From"
    if src_symbol:
        result += " %s: %s + %d (%s)" %(src_symbol[2], src_symbol[0], src_symbol[1], hex(ret_src))
    else:
        result += " %s" % hex(ret_src)
    result += " to"
    if dst_symbol:
        result += " %s: %s + %d (%s)\n" %(dst_symbol[2], dst_symbol[0], dst_symbol[1], hex(ret_dst))
    else:
        result += " %s\n" % hex(ret_dst)

    # sometimes state.block() raises exception, such as 'No bytes in block'
    # handle exception here
    try:
        block = state.block().capstone.insns
        result += "Insns:\n"
        for insn in block:
            result += '\t' + str(insn)+'\n'
    except Exception as ex:
        pass

    result += 'Args:\n'
    for reg, value in args.items():
        result += "\t%s: %s" % (reg, hex(value.args[0]))
        s = fetch_str(state, value)
        if s:
            result += " ->" + """ "%s" """%(s)
        s = state.project.symbol_resolve.reverse_resolve(value.args[0], must_plus = True)
        if s:
            if '__gmon_start__' in s[0]:
                s = list(s)
                s[0] = 'sub_%x'% value.args[0]
                s[1] = 0
            result += " (%s + %d)" % (s[0], s[1])
        result += '\n'

    return result


def call_cb_constructor(ana, **kwargs):
    def call_callback(state):
        # get info, and do some record
        ret_addr = state.memory.load(state.regs.rsp, 8, endness = 'Iend_LE')
        rsp = state.regs.rsp.args[0]
        #print(ret_addr)
        #print("now at", state.regs.rip)
        assert(ret_addr.concrete)
        ret_addr = ret_addr.args[0]
        ana.call_stack.append(ret_addr)
        ana.call_history.append((state.regs.rip.args[0],'call'))

        # make a write bp on return address in case of overflow
        # print("call:%s" % hex(rsp))
        origin_addr = state.memory.load(rsp, 8, endness = 'Iend_LE').args[0]
        ana.ret_bps[rsp] = (state.inspect.b("mem_write", when = angr.BP_AFTER, \
                                            action = bp_constructor(ana, rsp, origin_addr, 8)))
        
        # should we track this call?
        if ana._last_depth < ana.track_depth:
            # control flow has changed, log the call
            call_info = {'at':state.history.bbl_addrs[-1], \
                'to':state.inspect.function_address.args[0], \
                'type': 'call after overflow'}
            ana.abnormal_calls.append(call_info)
            ana._last_depth += 1
        return 
    return call_callback

# This cb trigged after 'ret'
def ret_cb_constructor(ana, **kwargs):
    """
    make a ret bp.

    1. compare the return address with address saved in call stack
    2. if not match, means we are in ROP/overflow condition
        reset the _last_depth now, cause we are in a new overflow
    """
    def ret_callback(state):
        # filter simprocedures
        at = state.history.bbl_addrs[-1]
        #print(hex(at))
        if at >> 12 == 0x3000:
            return
        ret_origin = 0
        ret_addr = state.regs.rip
        origin_rsp = state.regs.rsp.args[0] - 8
        assert(ret_addr.concrete)
        ret_addr = ret_addr.args[0]
        ana.call_history.append((ret_addr, 'ret'))

        # try to match ret address
        if ana.call_stack:
            if ret_addr in ana.call_stack:
                while 1:
                    temp = ana.call_stack.pop()
                    if temp == ret_addr:
                        break
                # TODO: fix call track
                if ana._last_depth and ana.call_track:
                    ana._last_depth -= 1
            else:
                # FIXME: only reset _last_depth on mismatching????
                ana.call_stack.pop()
                ana._last_depth = 0
                ana.call_track = 1
                ana.abnormal_calls.append({"at":state.history.bbl_addrs[-1], "to":ret_addr, "type":"mismatch"})
                message = "Strange return to %s" %hex(ret_addr)
                state.project.report_logger.warn(message, type='strange_return', return_to = ret_addr, \
                                                 ret_information = ret_info(state), \
                                                 state_timestamp = state_timestamp(state))
        else:
            # no frame? must be rop
            ana.call_track = 1
            ana.abnormal_calls.append({"at":state.history.bbl_addrs[-1], "to":ret_addr, "type":"unrecorded"})
            message = "Unrecorded return to %s" %hex(ret_addr)
            state.project.report_logger.warn(message, type='unrecorded_ret', return_to = ret_addr, \
            ret_information = ret_info(state), state_timestamp = state_timestamp(state))


        # print("ret:%s" % hex(origin_rsp))
        # remove the breakpoint
        removed = []
        for rsp, bp in ana.ret_bps.items():
            if rsp <= origin_rsp:
                removed.append(rsp)
                state.inspect.remove_breakpoint(event_type = 'mem_write', bp = bp)
        for i in removed:
            ana.ret_bps.pop(i)
        return

    return ret_callback




class call_analysis(object):
    """
    XXX: state.callstack plugin doesn't work under unciron
    Set bp on call and return, compare the address called and returned to, 
    so we can find stack's return address overflow.

    :ivar project:          project
    :ivar call_stack:       used to compare return address
    :ivar abnormal_calls:   record mismatch or abnormal return
    :ivar call_track:       tracks call info
    """
    def __init__(self, project, track_depth = 1):
        self.project = project
        self.call_stack = []
        self.abnormal_calls = []
        self.call_history = []
        self.call_cb = call_cb_constructor(self)
        self.ret_cb = ret_cb_constructor(self)
        self.bps = []
        self.ret_bps = {}
        self.call_track = 0
        self._last_depth = track_depth
        self.track_depth = track_depth
        self.overflow_pos = set()

    def clear(self):
        self.call_stack = []
        self.abnormal_calls = []
        self.call_history = []
        self.bps = []
        self.ret_bps = []


    def do_analysis(self):
        """
        do the job
        XXX: could we merge this to avoid simgr.run() again?
        """

        # if self.project.report_logger is in xxx_analysis.__init__(),
        # the self.project.report_logger will be set the last initialized one during Replayer.enable_analysis,
        # so get_logger should be put in xxx.do_analysis()
        self.project.report_logger = logger.get_logger(__name__)

        self.project.report_logger.info("Call analysis started.", type='tips')

        import time
        time_start = time.time()

        simgr = self.project.get_simgr()
        # XXX: unicorn engine at present cannot handle call/return breakpoint...
        self.bps.append(simgr.active[0].inspect.b("call", when = angr.BP_AFTER, action = self.call_cb))
        self.bps.append(simgr.active[0].inspect.b("return", when = angr.BP_AFTER, action = self.ret_cb))
        simgr.active[0] = set_state_options(simgr.active[0])

        simgr.run()

        time_end = time.time()
        res = "call time cost: %s s" % (time_end - time_start)
        with open("call.time", "w") as f:
            f.write(res)
            f.close()

        self.project.report_logger.info("Call analysis done.", type='tips')
        self.clear()

register_ana('call_analysis', call_analysis)
