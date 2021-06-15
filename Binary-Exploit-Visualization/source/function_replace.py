import claripy
import angr
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS
from angr.storage.memory_mixins.regioned_memory.abstract_address_descriptor import AbstractAddressDescriptor
from util.common import state_timestamp

import logging
l = logging.getLogger(name=__name__)

class strpbrk_rep(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, str1, str2):
        # print(str1)
        # print(str2)
        if self.state.solver.is_true(str1 == 0) or \
                self.state.solver.is_true(str2 == 0):
            return claripy.BVV(0, 64)
        addr1 = str1.args[0]
        while self.charAt(addr1) != 0:
            addr2 = str2.args[0]
            while self.charAt(addr2) != 0:
                if self.charAt(addr1) == self.charAt(addr2):
                    return claripy.BVV(addr1, 64)
                addr2 += 1
            addr1 += 1

        print(state_timestamp(self.state))

        return claripy.BVV(0, 64)

    def charAt(self, addr):
        ch = self.state.memory.load(addr, 0x1)
        return ch.args[0]

class strspn_rep(angr.SimProcedure):
    def run(self, str1, str2):
        count = 0
        addr1 = str1.args[0]
        while self.charAt(addr1) != 0:
            addr2 = str2.args[0]
            while self.charAt(addr2) != 0:
                if self.charAt(addr1) == self.charAt(addr2):
                    break
                addr2 += 1
            if self.charAt(addr2) == 0:
                return claripy.BVV(count, 64)
            count += 1
            addr1 += 1

        print(state_timestamp(self.state))
        return claripy.BVV(count, 64)

    def charAt(self, addr):
        ch = self.state.memory.load(addr, 0x1)
        return ch.args[0]

import angr.procedures.posix.gethostbyname

class time_rep(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, time_ptr):
        linux_time = angr.SIM_PROCEDURES['linux_kernel']['time']
        result = self.inline_call(linux_time, time_ptr).ret_expr
        print(state_timestamp(self.state))
        return result

function_set = {"strpbrk": strpbrk_rep(),
                "strspn": strspn_rep(),
                "time": time_rep()
                # "localtime":
                }

def init_function_replace(p):
    symbols = p.elfs[p.target].symbols
    for k, v in function_set.items():
        addr = symbols.get(k)
        if addr is not None:
            p.hook(addr, v)