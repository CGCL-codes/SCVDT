import sys
sys.path.append("../../source")

from replayer import Replayer


rr = Replayer("./fheap", "./syscalls.record", "./maps", '2.23', new_syscall=True)

rr.enable_analysis(["heap_analysis", "call_analysis", "got_analysis", "leak_analysis", "shellcode_analysis"])

rr.do_analysis()

rr.generate_report()

