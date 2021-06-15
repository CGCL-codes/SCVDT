import sys
sys.path.append("../../source")

from replayer import Replayer

rr = Replayer("./level5", "./syscalls.record", "./maps", "2.23", new_syscall=True)

rr.enable_analysis(["heap_analysis", "shellcode_analysis", "leak_analysis", "got_analysis", "call_analysis"])
rr.do_analysis()
rr.generate_report()

