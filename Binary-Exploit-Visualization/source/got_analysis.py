import angr
from symbol_resolve import symbol_resolve
from analysis import register_ana
import logger
from util.info_print import printable_callstack
from util.common import *

# TODO: test this function
class got_analysis(object):
    """
    Compare exploited_state's got with original func address.
    If got is not modified, it should point to the function, or plt stub in elf. 
    """
    def __init__(self, project):
        self.project = project
        self.symbol_resolve = symbol_resolve(project)
        self.report_logger = 0
        self.mismatch = {}
    
    def result_str(self):
        log_str = ""
        for k,v in self.mismatch.items():
            log_str += "%s: %s" %(k, hex(v["addr"]))
            if "sym" in v:
                log_str += " -> %s\n" % v["sym"]
            else:
                log_str += "\n"
        return log_str
    
    def trace_got(self):
        if self.mismatch == []:
            return
        main = self.project.elfs[self.project.target]
        ana = self
        state = self.project.get_entry_state()
        # state.options.discard("UNICORN")
        # state.options.add("SUPPORT_FLOATING_POINT")
        state = set_state_options(state)
        for sym in self.mismatch:
            addr = main.got[sym]
            def got_trace_bp(state):
                nonlocal ana, sym, addr
                bt = printable_callstack(state)
                changed = state.memory.load(addr, 8 , endness = "Iend_LE")
                changed = BV2Int(changed)
                message = "Found write to got table: %s" % sym
                ana.project.report_logger.warn(message, backtrace = bt, type='got_change', state_timestamp = state_timestamp(state))
            
            state.inspect.b("mem_write", action = got_trace_bp, when = angr.BP_AFTER,\
                mem_write_address=addr )

        simgr = self.project.factory.simgr(state)
        simgr.run()


    def do_analysis(self):
        """
        Do the job.
        """
        self.project.report_logger = logger.get_logger(__name__)

        self.project.report_logger.info("Got analysis started.", type='tips')

        import time
        time_start = time.time()


        if not self.project.exploited_state:
            self.project.report_logger.warning("Exploited state haven't been set! Do replay now...?", type='tips')
            # simgr = self.project.get_simgr()
            # simgr.run()
            self.project.do_track()

        assert(self.project.exploited_state)
        main = self.project.elfs[self.project.target]
        # save 'correct' got in origin_got
        # save exploited_state's got to exploited_got
        # e.g. xxx_got['puts'] = 0xdeadbeef
        origin_got = {}
        exploited_got = {}
        for sym in main.got:
            if sym == "__gmon_start__":
                continue
            # how to judge which file a symbol belongs to ??? 
            # XXX: now just iter over all objects
            for libname, obj in self.project.elfs.items():
                if libname == self.project.target:
                    continue
                if sym in obj.symbols:
                    if sym in origin_got:
                        origin_got[sym].append(obj.symbols[sym])
                    else:
                        origin_got[sym] = [obj.symbols[sym]]

            # then save exploited got to dict
            addr = main.got[sym]
            sym_addr = self.project.exploited_state.memory.load(addr, 8, endness = 'Iend_LE')
            assert(sym_addr.concrete)
            sym_addr = sym_addr.args[0]
            if sym_addr != 0:
                exploited_got[sym] = sym_addr
        
        self.origin_got = origin_got
        self.exploited_got = exploited_got
        
        # then compare addr with exploited state
        # assert(len(origin_got) == len(exploited_got))
        for sym, addr in exploited_got.items():
            # check if addr matched, or the symbol haven't been resolved 
            # don't trace 0 addr
            if addr == 0:
                continue
            if addr in origin_got[sym]:
                continue
            elif sym in main.plt:
                if main.plt[sym] == addr:
                    continue
                else:
                    resolve_result = self.symbol_resolve.reverse_resolve(addr)
                    self.mismatch[sym] = {"addr":addr}
                    if resolve_result:
                        message = "GOT mismatch: %s changed to %s%+d(%s)." % (sym, resolve_result[0], resolve_result[1], hex(addr))
                        self.project.report_logger.warn(message, got_entry_symbol = sym, modified_addr = addr, \
                                                        modified_to_func = resolve_result[0], \
                                                        modified_func_belongs_to = resolve_result[2], \
                                                        type='got_mismatch')
                    else:
                        message = "GOT mismatch: %s changed to %s." % (sym, hex(addr))
                        self.project.report_logger.warn(message, got_entry_symbol = sym, modified_addr = addr, type='got_mismatch')
        self.trace_got()

        time_end = time.time()
        res = "got time cost: %s s" % (time_end - time_start)
        with open("got.time", "w") as f:
            f.write(res)
            f.close()

        self.project.report_logger.info("Got analysis done.", type='tips')
            

register_ana('got_analysis', got_analysis)            
        
