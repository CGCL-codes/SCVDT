from replayer import Replayer
import os
from util.info_print import  stack_backtrace, printable_backtrace, printable_memory

# os.system("../../set-aslr.sh off")

rr = Replayer("./server", "./output.txt", "./maps.128811", new_syscall=True)

# rr = Replayer("./ptrace/mutil/thread_tests/thread", "./ptrace/mutil/thread_tests/stdin.txt", "./ptrace/mutil/thread_tests/maps.76058", test=True)

from parse_helpers import *



# dumps = parse_dumps(rr, "./maps.19158.dump")

# s = rr.get_entry_state()

simgr = rr.get_simgr()
simgr.run()
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
# list = simgr.active[0].history.bbl_addrs.hardcopy
# with open("log.log", 'w') as f:
#     str = ""
#     for addr in list:
#         str += hex(addr) + "\n"
#     f.write(str)
#     f.close()
print("over")
rr.enable_analysis(["heap_analysis"])
rr.do_analysis()
rr.generate_report()
# rr.packer.pack()