# -*- coding:utf-8 -*-
"""
This file contains helpers that do the input parse job.
XXX: Some system call stub related funcs still in this file, move to other place later.
"""

import claripy
import angr
from pwnlib import elf
from SimPacketsC import SimPacketsC


def parse_maps(maps, target):
    """
    Parse mmap_dump's memory map to angr.loaders's opts
    Returns angr.loader's main_opts and lib_opts.
    #TODO: now target can't be a path

    :param maps:    str, logged mmap content
    :param target:  target file name    
    
    """
    lib_opts = {}
    main_opts = {}
    maps = maps.split("\n")
    if "got bp" in maps[0]:
        bp = maps[0].split(" ")[-1].strip()
        bp = int(bp, 16)
    else:
        puts("No stack pointer recorded?")
        exit(0)
    for line in maps[1:]:
        if line == "":
            continue
        
        parts = line.split(" ")
        start_addr, end_addr = [int(x, 16) for x in parts[0].split("-")] #should work
        mod = parts[1]
        path = parts[-1]
        #set main_opts first
        if main_opts == {}:
            if path.split("/")[-1] == target:
                main_opts["base_addr"] = start_addr
                continue
        #than lib opts
            # use first addr as base
        if path not in lib_opts:
            # don't parse other segments of target
            if path.split("/")[-1] == target:
                continue
            # don't parse mapped memory
            if path == "":
                continue
            # don't parse misc segs like [heap]
            if path[0] == "[":
                continue
            lib_opts[path] = {"base_addr":start_addr}
    return main_opts, lib_opts, bp

def parse_maps_plus(maps):
    """
    Parse mmap_dump's memory map. Save all segments' infomation.
    #TODO: now target can't be a path

    :param maps:    str, logged mmap content
    :param target:  target file name    
    
    """
    parsed_maps = {}
    maps = maps.split("\n")
    if "got bp" in maps[0]:
        bp = maps[0].split(" ")[-1].strip()
        bp = int(bp, 16)
    else:
        print("No stack pointer recorded?")
        exit(0)
    for line in maps[1:]:
        if line == "":
            continue
        
        parts = line.split(" ")
        start_addr, end_addr = [int(x, 16) for x in parts[0].split("-")] #should work
        mod = parts[1]
        path = parts[-1]

        if path == "":
            if 'anonymous' in parsed_maps:
                parsed_maps['anonymous'].append({"start":start_addr, \
                    "end":end_addr, "mod":mod})
            else:
                parsed_maps['anonymous'] = [{"start":start_addr, \
                    "end":end_addr, "mod":mod}]
        
        elif path[0] == "[":
            path = path[1:-1]
        if path in parsed_maps:
            parsed_maps[path].append({"start":start_addr, \
                "end":end_addr, "mod":mod})
        else:
            parsed_maps[path] = [{"start":start_addr, \
                "end":end_addr, "mod":mod}]

    return parsed_maps
        



def parse_maps_from_file(path, target = None, plus = False):
    """
    wrapper for parse_maps
    Returns tuple(main_opts, lib_opts), both angr.loader's options
    """

    with open(path, "r") as f:
        if plus:
            return parse_maps_plus(f.read())
        else:
            assert(target)
            return parse_maps(f.read(), target)


#define LOGGER_PROMPT "$LOGGER$"
LOGGER_PROMPT = b"$LOGGER$"
#python3 version
def parse_log(log):
    """
    parse tee's logged stdin to sim_file
    Returns angr.SimPackets

    :param log: logged file content
    """
    #FIXME: input always has a 0 at beginning... don't use that
    packets = log.split(LOGGER_PROMPT+b"\x00")[1:]
    # prevent packet size unsat
    packets = [bytes(packet) for packet in packets]
    sim_file = SimPacketsC("sim-stream", content = packets)
    return sim_file


def parse_log_from_file(path):
    """
    wrapper for parse_log
    Returns angr.SimPackets
    """
    with open(path, "rb") as f:
        return parse_log(f.read())


def failed_stub_filter(state):
    rax = state.solver.eval(state.regs.rax)
    print(hex(rax))
    print((rax & 0x8000000000000000)!=0)
    # just consider rax < 0 means it failed
    if rax &0x8000000000000000:
        return True
    return False

def step_with_check(simgr):
    if simgr.active:
        simgr.step()
        # XXX: could there be more than 2 states after one step???
        if len(simgr.active) > 1:
            print(simgr.active)
            temp = simgr.active[0].regs.rax.args[0]
            print(simgr.active[0].regs.rax)
            print(temp)
            if "syscall_stub" in str(temp):
                print("Run into a syscall stub. Stash failed state.")
                print("got syscall:"+temp)
                if "execve" in str(temp):
                    return simgr
                simgr.stash(filter_func = failed_stub_filter)
            else:
                print("Got symbolic value in rax:")
                print(simgr.active[0].regs.rax.args)
            
                # only use first state
                simgr.active = simgr.active[:1]
    # FIXME: check if it is completed?
    return simgr

# XXX: rewrite these funcs
def is_failed_stub(state):
    temp = state.regs.rax.args[0]
    if isinstance(temp, int):
        return False
    else:
        if "syscall_stub" in temp:
            print("Run into a syscall stub.")
            return state.solver.eval(state.regs.rax)
        else:
            print("Unhandled retun value: "+temp)
            return False

# for unsupported syscall, always return 0
class success_syscall_stub(angr.SimProcedure):

    def run(self, resolves=None):

        self.resolves = resolves  # pylint:disable=attribute-defined-outside-init

        self.successors.artifacts['resolves'] = resolves

        return claripy.BVV(0, 64)

    def __repr__(self):
        if 'resolves' in self.kwargs:
            return '<Success Syscall stub (%s)>' % self.kwargs['resolves']
        else:
            return '<Success Syscall stub>'


# replace all unsupported syscall to success_syscall_stub
# dirty, but don't need to edit source code
def replace_stub(p, arch="amd64"):
    """
    Replace project's all unsupported syscall to a stub, 
    which always return 0.
    XXX: Default syscall stub returns an unconstrained value, cause mutiple paths
    """
    sl = p.simos.syscall_library
    for sysno, name in sl.syscall_number_mapping[arch].items():
        syscall = sl.get(sysno, arch, abi_list=[arch])
        if syscall.is_stub:
            #print("add %s" % name)
            sl.add(name, success_syscall_stub)
    
from binascii import unhexlify
def hex2str(h):
    h = hex(h)[2:]
    return unhexlify(h)



#python2 version
# def parse_log(log):
#     """
#     parse tee's logged stdin to sim_file

#     Args:
#         log: logged file content
    
#     Returns:
#         angr.SimPackets
#     """
#     #FIXME: input always has a 0 at beginning... don't use that
#     packets = log.split(LOGGER_PROMPT+"\x00")[1:]
#     # prevent packet size unsat
#     #packets = [claripy.BVV(i, len(i)*8) for i in packets]
#     sim_file = angr.SimPackets("sim-stream", content = packets)
#     return sim_file


# def parse_log_from_file(path):
#     """
#     wrapper for parse_log
    
#     Returns:
#         angr.SimPackets
#     """
#     with open(path, "r") as f:
#         return parse_log(f.read())




