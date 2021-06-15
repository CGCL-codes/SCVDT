import sys
sys.path.append("../../../source")

from replayer import Replayer
import angr
from claripy.ast.bv import BV
import claripy
import os
from util.info_print import  stack_backtrace, printable_backtrace, printable_memory

# os.system("../../set-aslr.sh off")

rr = Replayer("./easy_heap", "./output.txt", "./maps", "2.27", new_syscall=True)

# rr.do_track()
# a = claripy.BVV(0x603040, 64)
# b = claripy.BVV(0x603020, 64)
# print(a > b)
# rr.do_track()
# rr = Replayer("./ptrace/mutil/thread_tests/thread", "./ptrace/mutil/thread_tests/stdin.txt", "./ptrace/mutil/thread_tests/maps.76058", test=True)

from parse_helpers import *



# dumps = parse_dumps(rr, "./maps.19158.dump")

# s = rr.get_entry_state()

def bp_overflow():
    def write_bp(state):
        target_addr = state.inspect.mem_write_address
        target_size = state.inspect.mem_write_length
        content = state.inspect.mem_write_expr
        if "603040" in hex(content.args[0]):
            print("expr: %s" % content)
            print("state: %x" % state.addr)
        # if type(target_addr) != int:
        #     target_addr = target_addr.args[0]
        # if target_size is None:
        #     return
        # if type(target_size) != int:
        #     target_size = target_size.args[0]
        #
        # if (target_addr >= start_addr + size) \
        #         or (start_addr >= target_addr + target_size):
        #     return
        #
        #
        # if (target_addr + target_size > start_addr + size):
        #     overflow_len = target_addr + target_size - (start_addr + size)
        #     overflow_content = state.inspect.mem_write_expr[overflow_len * 8 - 1:0]
        #     memory = printable_memory(state, min(start_addr, target_addr), max(size, target_size) \
        #                               , warn_pos=start_addr + size, warn_size=overflow_len, info_pos=target_addr \
        #                               , info_size=target_size)
        #     message = "Found chunk overflow at %s." % hex(start_addr)
        #     report_logger.warn(message, type='heap_overflow', start_addr=start_addr, size=size, target_addr=target_addr, \
        #                        target_size=target_size, overflow_len=overflow_len, overflow_content=overflow_content, \
        #                        memory=memory, state_timestamp=state_timestamp(state))
        return

    return write_bp

# simgr = rr.get_simgr()
# simgr.active[0].options.discard("UNICORN")
# simgr.active[0].options.add("SUPPORT_FLOATING_POINT")
# simgr.active[0].inspect.b("mem_write", action = bp_overflow())
# simgr.run()
# while(True):
#     simgr.step()
#     if simgr.active[0].addr == 0x60307b:q

#         print(printable_memory(simgr.active[0], 0x603040, 0x20))
#         print("===================")
#     if simgr.active[0].addr == 0x60307b:
#         print(printable_memory(simgr.active[0], 0x603070, 0x20))
#         print("===================")
#     if simgr.active[0].addr == 0x60362a:
#         break
#     if len(simgr.active) == 0:
#         break
    # print(hex(simgr.active[0].addr))
# print("over")
# list = simgr.deadended[0].history.bbl_addrs.hardcopy
# with open("log.log", 'w') as f:
#     str = ""
#     for addr in list:
#         str += hex(addr) + "\n"
#     f.write(str)
#     f.close()
# print("over")
# rr.enable_analysis(["heap_analysis"])
rr.do_track()

import time
time_start = time.time()

rr.do_track()

time_end = time.time()
print("time cost: %s s" % (time_end-time_start))

res = "time cost: %s s" % (time_end - time_start)
with open("time.time", "w") as f:
    f.write(res)
    f.close()

rr.enable_analysis(["heap_analysis", "call_analysis", "got_analysis", "leak_analysis", "shellcode_analysis"])
rr.do_analysis()
rr.generate_report()
# now: read
# now: read
# INFO    | 2021-01-05 17:02:38,513 | shellcode_analysis | Found shellcode written at 0x1dc0040 (heap).
# Found exploited state: execve('/bin///sh', None, ...)
# Replay finished.
# time cost: 134.38854503631592 s

# now: read
# now: read
# INFO    | 2021-01-05 17:07:08,717 | shellcode_analysis | Found shellcode written at 0x1dc0040 (heap).
# Found exploited state: execve('/bin///sh', None, ...)
# Replay finished.
# time cost: 201.5395269393921 s

rr.generate_report()
# rr.packer.pack()
