"""
Generally, shellcode is placed in heap area and stack area.
When program is going to do `execve("/bin/sh"}`,
state's address might be in heap and stack.

Check the address in history.bbl_addrs from back to front;
Find the earliest state belong to shellcode and do some analysis ...
"""

import angr
import logger
from util.info_print import printable_memory, printable_backtrace, stack_backtrace
from analysis import register_ana
from util.common import *


def bp_shellcode(report_logger, start_addr, size, memory_content, pos, callback=None):
    def write_bp(state):
        target_addr = state.inspect.mem_write_address
        # target_size = state.inspect.mem_write_length

        if type(target_addr) != int:
            target_addr = target_addr.args[0]
        # if type(target_size) != int:
        #     target_size = target_size.args[0]
        target_expr = state.inspect.mem_write_expr
        target_size = target_expr.size() // state.arch.byte_width

        end_addr = start_addr + size
        if target_addr >= end_addr or \
            start_addr >= target_addr + target_size:
            return

        overlap_start = max(target_addr, start_addr)
        overlap_end = min(target_addr+target_size, end_addr)

        # target_expr = state.inspect.mem_write_expr exists some problems,
        # it is 'Iend_BE' when display read syscall's content
        target_expr = state.memory.load(target_addr, target_size, endness='Iend_LE')
        # target_expr_inspect = state.inspect.mem_write_expr
        # print(target_expr)
        # print(target_expr_inspect)
        overlap_expr = target_expr[(overlap_end-target_addr)*8-1:(overlap_start-target_addr)*8]
        memory_expr = memory_content[(overlap_end-start_addr)*8-1:(overlap_start-start_addr)*8]
        # print(memory_content)
        # print(target_expr)
        # print("addr :%s size:%s" % (hex(target_addr), hex(target_size)))
        # print("start: %s end: %s overlap_expr: %s" % ((overlap_end-target_addr)*8-1,(overlap_start-target_addr)*8,hex(overlap_expr.args[0])))
        # print("start: %s end: %s memory_expr: %s" % ((overlap_end-start_addr)*8-1,(overlap_start-start_addr)*8,hex(memory_expr.args[0])))

        # print("\n" + memory + "\n")
        if (overlap_expr == memory_expr).args[0]:
            print_start = min(start_addr, target_addr)
            print_start = (print_start >> 4) << 4
            memory = printable_memory(state, print_start, \
                                      max(end_addr, target_addr + target_size) - print_start, \
                                      warn_pos=overlap_start, warn_size=overlap_end - overlap_start, \
                                      info_pos=target_addr, info_size=target_size)
                                      # warn_pos=target_addr, warn_size=target_size, \
                                      # info_pos=overlap_start, info_size=overlap_end - overlap_start)
            bt = stack_backtrace(state)
            # print(memory)
            message = "Found shellcode written at %s (%s)." % (hex(target_addr), pos)
            report_logger.warn(message, type = "shell_write", \
                               start_addr=start_addr, size = size, \
                               target_addr = target_addr, target_size = target_size, \
                               shellcode_write = target_expr, memory = memory, \
                               backtrace = printable_backtrace(bt), \
                               exploit_method = state.project.exploited_state_method, \
                               state_timestamp = state_timestamp(state))

    return write_bp


def jump_state_bp(state):

    state.project.unhook(state.addr)
    bt = stack_backtrace(state)
    message = "Trace shellcode jump state at %s." % hex(state.addr)
    state.project.report_logger.warn(message, type = "shell_jump", \
                                     backtrace = printable_backtrace(bt), \
                                     state_timestamp = state_timestamp(state))

    # hook add the bbl_addrs's length, please delete it
    delete_state_bbl_addrs_length(state)



class shellcode_analysis(object):
    """
    Compare exploited_state's memory about shellcode with memory writting action.
    If the content of memory writting is the same with exploited_state's, it might be a shellcode written.
    """
    def __init__(self, project):
        self.project = project
        self._init_info()

    def _init_info(self):
        self._init_stack()
        self.heap_area = {}
        self.write_bp = []
        self._init_heap()
        self.cfg_sequence = self.project.cfg_sequence
        self.reverse_maps = self.project.reverse_maps

    def get_shellcode_state(self):
        """
        get the range of shellcode
        Returns a dict of shellcode state info
        """
        cfg_sequence = self.project.cfg_sequence

        def _address_lookup(addr, reverse_maps, heap_area):
            page =  addr >> 12
            if page in reverse_maps:
                return reverse_maps[page]
            if "start" in heap_area.keys() and heap_area["start"] <= addr <= heap_area["end"]:
                return ("heap", None)
            else:
                return -1

        def _get_state_size(addr, state):
            block = state.project.factory.block(addr)
            size = block.size
            return size

        # def _get_block_insns(state, addr, size=None):
        #     asm_insns = ""
        #     block = state.project.factory.block(addr)
        #     insns = block.capstone.insns
        #     for insn in insns:
        #         asm_insns += '\t' + str(insn)+'\n'
        #     return asm_insns

        shell_start = 0
        shell_end = 0
        shell_state_list = []
        jump_state = None
        for i in range(len(cfg_sequence)-1, -1, -1):
            curr_addr = cfg_sequence[i]
            owner = _address_lookup(curr_addr, self.reverse_maps, self.heap_area)
            # if owner is -1, maybe the addr is in syscall of angr
            if owner == -1:
                pass
            # if addr is in heap or stack, record it
            elif owner[0] == "heap" or owner[0] == "stack":
                pos = owner[0]
                # ensure the address recorded are in same area
                if shell_start != 0 and pos != shell_start[1]:
                    continue
                shell_start = (curr_addr, pos)
                if shell_end == 0:
                    shell_end = (curr_addr, pos)
                shell_state_list.insert(0, {"addr": curr_addr, "pos": pos})
            else:
                jump_state = {"addr": curr_addr, "pos": owner[0]}
                break

        if shell_start == 0:
            return [], -1
        if shell_end[0] < shell_start[0]:
            return [], -1

        exploited_state = self.project.exploited_state
        shell_state_merged_list = []
        for i in range(0, len(shell_state_list)):
            curr_state = shell_state_list[i]
            state_size = _get_state_size(curr_state["addr"], exploited_state)
            curr_state["size"] = state_size
            # Merge adjacent state ???
            # if len(shell_state_merged_list)>0 and \
            #         shell_state_merged_list[-1]["addr"]+shell_state_merged_list[-1]["size"]+1 >= curr_state['addr']:
            #     # the last state in list
            #     merged_size = curr_state["addr"]+state_size-shell_state_merged_list[-1]["addr"]
            #     shell_state_merged_list[-1]["size"] = merged_size
            #     shell_state_merged_list[-1]["content"] = exploited_state.memory.load(shell_state_merged_list[-1]["addr"], \
            #                                                                   merged_size, \
            #                                                                   endness='Iend_LE')
            #     continue
            curr_content = exploited_state.memory.load(curr_state["addr"], \
                                                       state_size, \
                                                       endness='Iend_LE')
            curr_state["content"] = curr_content
            shell_state_merged_list.append(curr_state)

        # resolve state's insns
        # for i in range(0, len(shell_state_merged_list)):
        #     curr_state = shell_state_merged_list[i]
        #     curr_state["insns"] = _get_block_insns(exploited_state, curr_state["addr"])

        return shell_state_merged_list, jump_state


    def _init_stack(self):
        """
        get the range of stack area
        start: xxxx
        end: xxxx
        """
        if "stack" not in self.project.maps:
            print("Do not resolve stack information!")
            return
        self.stack_area = self.project.maps["stack"][0]

    def _init_heap(self):
        """
        get the range of heap area
        start: xxxx
        end: xxxx
        """
        if len(self.project.brk_address) >= 2:
            self.heap_area["start"] = self.project.brk_address[0]
            self.heap_area["end"] = self.project.brk_address[-1]
            print("start:%s end:%s" % (hex(self.heap_area['start']), hex(self.heap_area['end'])))
            return
        # print("Heap may be not initialized?")


    def trace_shell(self, shellcode_state_list, jump_state):
        """
        find the write breakpoint about shellcode memory
        """
        simgr = self.project.get_simgr()
        simgr.active[0] = set_state_options(simgr.active[0])
        simgr.active[0].project.hook(jump_state["addr"], jump_state_bp)
        for i in range(0, len(shellcode_state_list)):
            shell_state = shellcode_state_list[i]
            shell_start = shell_state["addr"]
            shell_size = shell_state["size"]
            shell_memory = shell_state["content"]
            shell_pos = shell_state["pos"]
            bp = simgr.active[0].inspect.b("mem_write", when = angr.BP_AFTER, action = \
                bp_shellcode(self.project.report_logger, shell_start, shell_size, shell_memory, shell_pos))
            self.write_bp.append(bp)
        simgr.run()
        return

    def do_analysis(self):
        """
        do the job
        """
        self.project.report_logger = logger.get_logger(__name__)

        self.project.report_logger.info("Shellcode analysis started.", type='tips')

        import time
        time_start = time.time()

        if not self.project.exploited_state:
            self.project.report_logger.info("Exploited state haven't been set! Do replay now...?", type='tips')
            self.project.do_track()

            assert (self.project.exploited_state)

        self._init_info()
        shellcode_state_list, jump_state = self.get_shellcode_state()
        # print(shellcode_state_list)
        if len(shellcode_state_list) == 0 and jump_state == -1:
            message = "Do not find a possible shellcode area!"
            self.project.report_logger.info(message, type='tips')
            return
        # self.report_logger.info("Find a possible shellcode!", shellcode_state_list=shellcode_state_list, type='list')

        symbol_info =  self.project.symbol_resolve.reverse_resolve(jump_state["addr"])
        if symbol_info is not None:
            symbol_addr = "%s+%s" % (symbol_info[0], symbol_info[1])
        self.project.report_logger.warn("Find a shellcode jump state at %s." % hex(jump_state["addr"]), type='jump_to_shell', \
                                jump_state_addr=jump_state["addr"], jump_state_pos=jump_state["pos"], \
                                        symbol_addr=symbol_addr)
        self.trace_shell(shellcode_state_list, jump_state)

        time_end = time.time()
        res = "shellcode time cost: %s s" % (time_end - time_start)
        with open("shellcode.time", "w") as f:
            f.write(res)
            f.close()

        self.project.report_logger.info("Shellcode analysis done.", type='tips')
        return

register_ana('shellcode_analysis', shellcode_analysis)





