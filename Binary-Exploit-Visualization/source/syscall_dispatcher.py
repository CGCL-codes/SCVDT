import angr
import claripy
import base64

# wait, angr makes a copy of a SimProcedure() when the procedure is triggered
# so we have to use a global variable to save static variable
from util.common import state_timestamp

dispatch_index = {}

# Fixme: is this way useful?
# the flag to record the state if going to the first syscall state
first_syscall_state = None

class syscall_dispatcher(angr.SimProcedure):
    def __init__(self, sysno, name = ""):
        super().__init__()
        self.sysno = sysno
        self.posix_cb = []
        self.name = name
        self.is_stub = False
        dispatch_index[sysno] = 0
        

    def set_callinfo(self, syscall_info):
        # last syscall may fail
        if len(syscall_info) & 1:
            self.syscall_info = syscall_info[:-1]
        else:
            self.syscall_info = syscall_info

    def __repr__(self):
        if 'resolves' in self.kwargs:
            return '<Success Syscall stub (%s)>' % self.kwargs['resolves']
        elif self.name:
            return '<Syscall Dispatcher for %s>' % self.name
        else:
            return '<Syscall Dispatcher for %d>' % self.sysno

    def construct_default_result(self):
        rdi = self.state.regs.rdi.args[0]
        rsi = self.state.regs.rsi.args[0]
        rbp = self.state.regs.rbp.args[0]
        rdx = self.state.regs.rdx.args[0]
        rip = self.state.regs.rip.args[0]
        call_info = {"sysno":self.sysno, "rdi":rdi, "rsi":rsi, "rdx":rdx, "rbp":rbp, "rip":rip}
        result_info = {"sysno":self.sysno, "is_result": True, "rax":rdx}
        return call_info, result_info


    def next_info(self):
        idx = dispatch_index[self.sysno]
        result = self.syscall_info[idx:idx+2]
        dispatch_index[self.sysno] += 2
        #assert(result[1]["is_result"])

        if result:
            assert(result[1]["is_result"])
        else:
            result = self.construct_default_result()
        return result
    
    def recover_memory(self, mem_change):
        content = base64.b64decode(mem_change["content"])
        size = mem_change["size"]
        addr = mem_change["addr"]
        #print("Recovering %#x with logged content(size %#x)" %(addr, size))
        assert(len(content) == size)
        self.state.memory.store(addr, claripy.BVV(content))

    def log(self):
        # pass
        # print("[%s]now: %s"%(state_timestamp(self.state), self.name))
        message = "syscall<%s>: %s" %(self.sysno, self.name)
        if isinstance(self.state.project.report_logger, int):
            print("syscall<%s>: %s" %(self.sysno, self.name))
        else:
            if self.sysno in syscall_output_dict.keys():
                self.state.project.report_logger.debug(message, type="syscall", \
                                              state_timestamp = state_timestamp(self.state))

    def check_call_info(self, call_info):
        rbp = call_info["rbp"]
        rip = call_info["rip"]
        rdi = call_info["rdi"]
        rsi = call_info["rsi"]
        rdx = call_info["rdx"]

        state_rbp = self.state.regs.rbp.args[0]
        state_rip = self.state.regs.rip.args[0]
        state_rdi = self.state.regs.rdi.args[0]
        state_rsi = self.state.regs.rsi.args[0]
        state_rdx = self.state.regs.rdx.args[0]

        if rbp == state_rbp and rip == state_rip and \
            rdi == state_rdi and rsi == state_rsi and \
            rdx == state_rdx:
            return 1
        else:
            return 0

    # default run for syscall dispatcher    
    def run(self, resolves=None):
        self.state.project.from_syscall = 1
        # angr's template
        self.resolves = resolves  # pylint:disable=attribute-defined-outside-init
        self.successors.artifacts['resolves'] = resolves

        # true run func
        self.log()
        call_info, ret_info = self.next_info()
        if "mem_changes" in ret_info:
            for mem_change in ret_info["mem_changes"]:
                self.recover_memory(mem_change)


        return claripy.BVV(ret_info["rax"], 64)


class open_dispatcher(syscall_dispatcher):
    def run(self, p_addr):
        self.state.project.from_syscall = 1
        self.log()
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        path_state = self.state.solver.eval(p_expr, cast_to=bytes)

        call_info, ret_info = self.next_info()
        rdi = call_info["rdi"]
        p_strlen = self.inline_call(strlen, rdi)
        p_expr = self.state.memory.load(rdi, p_strlen.max_null_index, endness='Iend_BE')
        path_log = self.state.solver.eval(p_expr, cast_to=bytes)

        if path_log == path_state:
            fs_struct = {"path": path_log, "type":"file", "content":[], "last_fd":ret_info["rax"]}
            self.state.project.fake_fs.append(fs_struct)
            self.state.project.fdset[ret_info["rax"]] = len(self.state.project.fake_fs) - 1
        else:
            print(path_log, path_state)

        return claripy.BVV(ret_info["rax"], 64)


class stat_dispatcher(syscall_dispatcher):
    pass


class fstat_dispatcher(syscall_dispatcher):
    pass


class lstat_dispatcher(syscall_dispatcher):
    pass


class socket_dispatcher(syscall_dispatcher):
    def run(self):
        self.state.project.from_syscall = 1
        self.log()
        # print("in socket")
        call_info, ret_info = self.next_info()
        fs_struct = {"path": "", "type": "socket", "content":[], "last_fd":ret_info["rax"]}
        self.state.project.fake_fs.append(fs_struct)
        self.state.project.fdset[ret_info["rax"]] = len(self.state.project.fake_fs) - 1
        return claripy.BVV(ret_info["rax"], 64)

class accept_dispatcher(socket_dispatcher):
    pass

class connect_dispatcher(syscall_dispatcher):
    pass

class read_dispatcher(syscall_dispatcher):
    def run(self, fd, buf, size):
        self.state.project.from_syscall = 1
        self.log()
        call_info, ret_info = self.next_info()
        #assert(fd.args[0] == call_info["rdi"])
        #assert(size.args[0] >= call_info["rdx"])

        # fs_struct = self.state.project.fake_fs[self.state.project.fdset[fd.args[0]]]
        if "mem_changes" in ret_info:
            mem_change = ret_info["mem_changes"][0]
            mem_change["addr"] = buf.args[0]
            self.recover_memory(mem_change)
            # if fs_struct:
            #     fs_struct["content"].append(b"-" + base64.b64decode(mem_change["content"]))
                #print(b"Applying input: " + base64.b64decode(mem_change["content"]))

        return claripy.BVV(ret_info["rax"], 64)


class ioctl_dispatcher(syscall_dispatcher):
    def run(self, fd, cmd, content):
        self.state.project.from_syscall = 1
        # print("in ioctl")
        self.log()
        call_info, ret_info = self.next_info()

        # if "mem_changes" in ret_info:
        #     mem_change = ret_info["mem_changes"][0]
        #     mem_change["addr"] = content.args[0]
        #     self.recover_memory(mem_change)
        return claripy.BVV(ret_info["rax"], 64)

class recvfrom_dispatcher(read_dispatcher):
    pass

class recvmsg_dispatcher(read_dispatcher):
    def run(self, fd, buf, size):
        self.state.project.from_syscall = 1
        self.log()
        call_info, ret_info = self.next_info()
        assert(fd.args[0] == call_info["rdi"])
        assert(size.args[0] == call_info["rdx"])

        if "mem_changes" in ret_info:
            fs_struct = self.state.project.fake_fs[self.state.project.fdset[fd.args[0]]]
            mem_change = ret_info["mem_changes"][0]
            if fs_struct:
                fs_struct["content"].append(b"-" + base64.b64decode(mem_change["content"]))

            for mem_change in ret_info["mem_changes"]:
                self.recover_memory(mem_change)

        return claripy.BVV(ret_info["rax"], 64)


class alarm_dispatcher(syscall_dispatcher):
    def run(self):
        return claripy.BVV(0, 64)


class write_dispatcher(syscall_dispatcher):
    def run(self, fd, buf, size):
        self.state.project.from_syscall = 1
        self.log()
        call_info, ret_info = self.next_info()

        # print("%s %s %s" % (hex(fd.args[0]), hex(buf.args[0]), hex(size.args[0])))
        # print(call_info)
        # assert(fd.args[0] == call_info["rdi"])
        if (size.args[0]!= call_info["rdx"]):
            print("callsite rdx: %#x, logged rdx: %#x" % (size.args[0], call_info["rdx"]))

        # if "mem_changes" in ret_info:
        #     mem_change = ret_info["mem_changes"][0]
        #     fs_struct = self.state.project.fake_fs[self.state.project.fdset[fd.args[0]]]
        #     if fs_struct:
        #         fs_struct["content"] = fs_struct["content"]+(base64.b64decode(mem_change["content"]))

        # write to posix.dumps(1) for leak_analysis
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            pass
        else:
            simfd.write(buf, size)

        return claripy.BVV(ret_info["rax"], 64)


class close_dispatcher(syscall_dispatcher):
    pass


class select_dispatcher(syscall_dispatcher):
    pass


class sendto_dispatcher(write_dispatcher):
    pass


class sendmsg_dispatcher(write_dispatcher):
    pass


class poll_dispatcher(syscall_dispatcher):
    pass


class lseek_dispatcher(syscall_dispatcher):
    pass


class getrandom_dispatcher(syscall_dispatcher):
    def run(self, buf, size):
        self.state.project.from_syscall = 1
        self.log()
        call_info, ret_info = self.next_info()
        if "mem_changes" in ret_info:
            mem_change = ret_info["mem_changes"][0]
            mem_change["addr"] = buf.args[0]
            self.recover_memory(mem_change)

        return claripy.BVV(ret_info["rax"], 64)

class writev_dispatcher(syscall_dispatcher):
    def run(self, fd, vec, vlen):
        self.state.project.from_syscall = 1
        # true run func
        self.log()
        # print("in writev")
        call_info, ret_info = self.next_info()
        retval = ret_info["rax"]

        return claripy.BVV(0x56, 64)


class rt_sigaction_dispatcher(syscall_dispatcher):
    pass


class brk_dispatcher(syscall_dispatcher):
    """
    This implements the brk system call.
    """

    # pylint:disable=arguments-differ
    def run(self, new_brk):
        self.state.project.from_syscall = 1

        # def _set_brk(posix, new_brk):
        self.log()
        call_info, ret_info = self.next_info()
        if new_brk.args[0] == 0:
            self.state.posix.brk = claripy.BVV(ret_info["rax"], 64)
        r = self.state.posix.set_brk(new_brk)
        new_brk = r.args[0]
        # print("in brk")

        project = self.state.project
        # if heap analysis running, record the heap base addr
        if hasattr(project, "heap_analysis"):
            heap_analysis = project.heap_analysis

            heap_analysis.brk_address.append(r.args[0])
            if self.state.project.heap_analysis.is_heap_init is False and \
                    len(heap_analysis.brk_address) == 2:
                heap_analysis.is_heap_init = True
                heap_analysis.heapbase = heap_analysis.brk_address[0]
                print("heapbase %x" % heap_analysis.heapbase)
                # heap_analysis.brk_address = []

        if new_brk not in project.brk_address:
            if len(project.brk_address) == 0 or \
                    new_brk > project.brk_address[-1]:
                # print("new brk: %s" % hex(new_brk))
                project.brk_address.append(new_brk)

        return r


class getsockopt_dispatcher(syscall_dispatcher):
    pass


class fcntl_dispatcher(syscall_dispatcher):
    pass


class statfs_dispatcher(syscall_dispatcher):
    pass


class clock_getres_dispatcher(syscall_dispatcher):
    pass


import time


class clock_gettime_dispathcer(syscall_dispatcher):
    def run(self, which_clock, timespec_ptr):
        # if not self.state.solver.is_true(which_clock == 0):
        #     raise angr.errors.SimProcedureError("clock_gettime doesn't know how to deal with a clock other than CLOCK_REALTIME")
        # print(timespec_ptr)
        if self.state.solver.is_true(timespec_ptr == 0):
            return -1

        # if angr.options.USE_SYSTEM_TIMES in self.state.options:
        flt = time.time()
        result = {'tv_sec': int(flt), 'tv_nsec': int(flt * 1000000000)}
        # else:
        #     result = {
        #         'tv_sec': self.state.solver.BVS('tv_sec', self.arch.bits, key=('api', 'clock_gettime', 'tv_sec')),
        #         'tv_nsec': self.state.solver.BVS('tv_nsec', self.arch.bits, key=('api', 'clock_gettime', 'tv_nsec')),
        #     }

        self.state.mem[timespec_ptr].struct.timespec = result
        return 0



##### junk warning 
import angr
from angr.storage.file import SimFileDescriptor

import logging
l = logging.getLogger(name=__name__)


PROT_READ       = 0x1  #    /* Page can be read.  */
PROT_WRITE      = 0x2  #    /* Page can be written.  */
PROT_EXEC       = 0x4  #    /* Page can be executed.  */
PROT_NONE       = 0x0  #    /* Page can not be accessed.  */
MAP_SHARED      = 0x01 #    /* Share changes.  */
MAP_PRIVATE     = 0x02 #    /* Changes are private.  */
MAP_ANONYMOUS   = 0x20 #    /* Don't use a file.  */
MAP_FIXED       = 0x10 #    /* Interpret addr exactly.  */


class mmap_dispatcher(syscall_dispatcher):

    def run(self, addr, length, prot, flags, fd, offset): #pylint:disable=arguments-differ,unused-argument
        #if self.state.solver.symbolic(flags) or self.state.solver.eval(flags) != 0x22:
        #   raise Exception("mmap with other than MAP_PRIVATE|MAP_ANONYMOUS unsupported")
        self.log()
        self.state.project.from_syscall = 1
        call_info, ret_info = self.next_info()
        ret_addr = ret_info["rax"]
        # if ret_addr == 0x00007ffff772d000 or ret_addr == 0x7ffff7523000:
        #     print("pause")
        self.state.heap.mmap_base = ret_addr

        #
        # File descriptor sanity check
        #
        # sim_fd = None
        # if self.state.solver.is_false(fd[31:0] == -1):
        #     if self.state.solver.symbolic(fd):
        #         raise angr.errors.SimPosixError("Can't map a symbolic file descriptor!!")
        #     if self.state.solver.symbolic(offset):
        #         raise angr.errors.SimPosixError("Can't map with a symbolic offset!!")
        #     sim_fd = self.state.posix.get_fd(fd)
        #     if sim_fd is None:
        #         l.warning("Trying to map a non-exsitent fd")
        #         return -1
        #     if not isinstance(sim_fd, SimFileDescriptor) or sim_fd.file is None:
        #         l.warning("Trying to map fd not supporting mmap (maybe a SimFileDescriptorDuplex?)")
        #         return -1



        #
        # Length
        #

        if self.state.solver.symbolic(length):
            size = self.state.solver.max_int(length)
            if size > self.state.libc.max_variable_size:
                l.warning("mmap size requested of %d exceeds libc.max_variable_size. Using size %d instead.", size,self.state.libc.max_variable_size)
                size = self.state.libc.max_variable_size
        else:
            size = self.state.solver.eval(length)

        #
        # Addr
        #

        # Not handling symbolic addr for now
        addrs = self.state.solver.eval_upto(addr,2)
        if len(addrs) == 2:
            err = "Cannot handle symbolic addr argument for mmap."
            l.error(err)
            raise angr.errors.SimPosixError(err)

        addr = addrs[0]

        # Call is asking for system to provide an address
        if addr == 0:
            addr = self.allocate_memory(size)

        #
        # Flags
        #

        # Only want concrete flags
        flags = self.state.solver.eval_upto(flags, 2)

        if len(flags) == 2:
            err = "Cannot handle symbolic flags argument for mmap."
            l.error(err)
            raise angr.errors.SimPosixError(err)

        flags =  flags[0]

        # Sanity check. All mmap must have exactly one of MAP_SHARED or MAP_PRIVATE
        if (flags & MAP_SHARED and flags & MAP_PRIVATE) or flags & (MAP_SHARED | MAP_PRIVATE) == 0:
            l.debug('... = -1 (bad flags)')
            return self.state.solver.BVV(-1, self.state.arch.bits)

        # print("addr:%s size:%s" % (hex(addr), hex(size)))
        # Do region mapping
        while True:
            try:
                self.state.memory.map_region(addr, size, prot[2:0], init_zero=bool(flags & MAP_ANONYMOUS))
                l.debug('... = %#x', addr)
                break

            except angr.SimMemoryError:
                # This page is already mapped

                if flags & MAP_FIXED:
                    l.debug('... = -1 (MAP_FIXED failure)')
                    break
                    # return self.state.solver.BVV(-1, self.state.arch.bits)

                # Can't give you that address. Find a different one and loop back around to try again.
                addr = self.allocate_memory(size)

        if "mem_changes" in ret_info:
            for mem_change in ret_info["mem_changes"]:
                self.recover_memory(mem_change)

        # If the mapping comes with a file descriptor
        # if sim_fd:
        #     if not sim_fd.file.seekable:
        #         raise angr.errors.SimPosixError("Only support seekable SimFile at the moment.")
        #
        #     prot = self.state.solver.eval_exact(prot, 1)[0]
        #
        #     if prot & PROT_WRITE:
        #         l.warning("Trying to map a file descriptor backed by a file")
        #         l.warning("Updates to the mapping are not carried through to the underlying file")
        #
        #     # read data
        #     saved_pos = sim_fd.tell()
        #     sim_fd.seek(self.state.solver.eval(offset), whence="start")
        #     data, _ = sim_fd.read_data(size)
        #     sim_fd.seek(saved_pos, whence="start")
        #     self.state.memory.store(addr, data)
        return addr

    def allocate_memory(self,size):

        addr = self.state.heap.mmap_base
        new_base = addr + size

        if new_base & 0xfff:
            new_base = (new_base & ~0xfff) + 0x1000

        self.state.heap.mmap_base = new_base

        return addr
###### junk end


class mmap_replace(mmap_dispatcher):
    pass


class getpgrp_dispatcher(syscall_dispatcher):
    pass

syscall_output_dict = {
    0:"read",
    2:"open",
    7:"poll",
    9:"mmap",
    12:"brk",
    16:"ioctl",
    23:"select",
    41:"socket",
    42:"connect",
    43:"accept",
    45:"recvfrom",
    47:"recvmsg",
    55:"getsockopt"
}

dispatchers = {0 : read_dispatcher(0, "read"),
              1 : write_dispatcher(1, "write"),
              2 : open_dispatcher(2, "open"),
              3 : close_dispatcher(3, "close"),
              4 : stat_dispatcher(4, "stat"),
              5 : fstat_dispatcher(5, "fstat"),
              6 : lstat_dispatcher(6, "lstat"),
              7 : poll_dispatcher(7, "poll"),
              8 : lseek_dispatcher(8, "lseek"),
              9 : mmap_dispatcher(9, "mmap"),
              12 : brk_dispatcher(12, "brk"),
              13 : rt_sigaction_dispatcher(13, "rt_sigaction"),
              16 : ioctl_dispatcher(16, "ioctl"),
              20 : writev_dispatcher(20, "writev"),
              23 : select_dispatcher(23, "select"),
              37 : alarm_dispatcher(37, "alarm"),
              41 : socket_dispatcher(41, "socket"),
              42 : connect_dispatcher(42, "connect"),
              43 : accept_dispatcher(43, "accept"),
              44 : sendto_dispatcher(44, "sendto"),
              46 : sendmsg_dispatcher(46, "sendmsg"),
              45 : recvfrom_dispatcher(45, "recvfrom"),
              47 : recvmsg_dispatcher(47, "recvmsg"),
              55 : getsockopt_dispatcher(55, "getsockopt"),
              72 : fcntl_dispatcher(72, "fcntl"),
              111 : getpgrp_dispatcher(111, "getpgrp"),
              137 : statfs_dispatcher(137, "statfs"),
              228 : clock_gettime_dispathcer(228, "clock_gettime"),
              229 : clock_getres_dispatcher(229, "clock_getres"),
              318 : getrandom_dispatcher(318, "getrandom"),
              }

def reset_dispatchers():
    for i in dispatch_index:
        dispatch_index[i] = 0




