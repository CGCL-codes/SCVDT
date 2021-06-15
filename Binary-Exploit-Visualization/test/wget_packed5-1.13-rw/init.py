import sys
sys.path.append("../../source")

from replayer import Replayer

rr = Replayer("./wget", "./syscalls.record", "./maps", new_syscall=True)

rr.enable_analysis(["call_analysis", "heap_analysis", "shellcode_analysis"])
rr.do_analysis()

rr.generate_report()

