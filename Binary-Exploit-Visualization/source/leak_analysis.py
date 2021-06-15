"""
Analysis to find information leakage in exploited state.
Use heuristic way to find leaked address from exploited_state's stdout. It doesn't work well
in most situation :(
"""

import struct
from symbol_resolve import symbol_resolve
from analysis import register_ana
import logger
from util.info_print import printable_callstack
from util.common import *


class leak_analysis(object):
    """
    Use heuristic way to find leaked address from exploited_state's stdout.
    Assume each loaded object is samller than 16MB, so the higher 3 bytes in
    address is always the same with object's base addr.
    Also, low bytes of address is usually useless in exploit, so we check leaked higher 
    three bytes to find leak.

    XXX: if we have 140737349736160 in output, which is actually an address, how can we
    find out that?

    :ivar project:          project of the analysis
    :ivar leaked_addrs:     all address that could be leak in stdout(and others).
    :ivar symbol_resolve:   helper to get symbol name from address
    """
    def __init__(self, project):
        self.project = project
        self.symbol_resolve = symbol_resolve(project)
        self._prefixs = []
        self.leaked_addrs = []
        self.leaked_symbols = []
        self._find_prefix()
        self.report_logger = 0


    def _find_prefix(self):
        maps = self.project.maps
        for obj, segs in maps.items():
            for seg in segs:
                # use high 3 bytes as prefix
                # XXX: this assumes every segment is smaller than 16MB
                prefix = (seg['start'] >> (4*6)) & 0xffffff
                if prefix == 0 or prefix == 0xffffff:
                    continue
                prefix = struct.pack("<I", prefix)[:3]
                self._prefixs.append(prefix)


        self._prefixs = list(set(self._prefixs))

    def _match_output(self, prefix, output):
        """
        find address with specific prefix in output
        """
        pos_list = []
        pos = output.find(prefix)
        end = len(output)
        while pos!=-1:
            pos_list.append(pos)
            pos = output.find(prefix, pos + 1, end) 

        
        #try to get full addr, and unpack
        for pos in pos_list:
            if pos + 3 > end:
                continue
            addr = output[pos-3:pos+3] + b'\x00\x00'
            addr = struct.unpack("<Q", addr)[0]
            self.leaked_addrs.append(addr)

        for i in self.leaked_addrs:
            result = self.symbol_resolve.reverse_resolve(i)
            if result:
                self.leaked_symbols.append({"addr":i, "symbol":result})


    def do_report(self):
        for i in self.leaked_symbols:
            message = "Found leakage: %s%+d(%s)"%((i["symbol"][0]), i["symbol"][1], hex(i["addr"]))
            self.project.report_logger.warn(message, type="leak",leaked_address = i["addr"], symbol_of_address = i["symbol"][0], offset = i["symbol"][1], lib = i["symbol"][2])

    def trace_leak(self):
        if self.leaked_addrs == []:
            return
        self.project.report_logger.info("Start tracing of leakage.", type="tips")
        addrs = self.leaked_addrs
        def find_func(state, get_addr = False):
            nonlocal addrs
            for i in addrs:
                if struct.pack("<Q", i)[:6] in state.posix.dumps(1):
                    if get_addr:
                        return i
                    return True
                else:
                    return False
        simgr = self.project.get_simgr()
        # simgr.active[0].options.discard("UNICORN")
        # simgr.active[0].options.add("SUPPORT_FLOATING_POINT")
        simgr.active[0] = set_state_options(simgr.active[0])
        simgr.explore(find = find_func)
        if "found" in simgr.stashes:
            state = simgr.stashes["found"][0]
            rip = BV2Int(state.regs.rip)
            bt = printable_callstack(state)
            addr = find_func(state, get_addr=True)
            symbol = []
            for i in self.leaked_symbols:
                if i["addr"]==addr:
                    symbol = i["symbol"]
            if symbol:
                message = "Leakage trace: leak of %s%+d (%s) happened at :%s" %(symbol[0], symbol[1],hex(addr), hex(rip))
            # else:
            #     message = "Leakage trace: leak happend at :%s" % (hex(addr), hex(rip))
                self.project.report_logger.warn(message, backtrace = bt, type='leak_trace', state_timestamp = state_timestamp(state))
        else:
            self.project.report_logger.warning("Track leak failed.", type="tips")
        
        return simgr
    
    def do_analysis(self):
        """
        do the job
        """
        self.project.report_logger = logger.get_logger(__name__)

        self.project.report_logger.info("leak analysis started.", type='tips')

        import time
        time_start = time.time()

        if not self.project.exploited_state:
            # print("No exploited state to analyse!")
            self.project.report_logger.warning("Exploited state haven't been set! Do replay now...?", type='tips')
            self.project.do_track()
        output = self.project.exploited_state.posix.dumps(1)
        for prefix in self._prefixs:
            self._match_output(prefix, output)
        self.do_report()
        self.trace_leak()

        time_end = time.time()
        res = "leak time cost: %s s" % (time_end - time_start)
        with open("leak.time", "w") as f:
            f.write(res)
            f.close()

        self.project.report_logger.info("Leak analysis done.", type='tips')
        
    
register_ana('leak_analysis', leak_analysis)
