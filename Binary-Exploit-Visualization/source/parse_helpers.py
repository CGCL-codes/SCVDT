# -*- coding:utf-8 -*-
"""
This file contains helpers that do the input parse job.
XXX: Some system call stub related funcs still in this file, move to other place later.
"""

import claripy
import angr
from pwnlib import elf
from SimPacketsC import SimPacketsC
import base64
from syscall_dispatcher import  dispatchers , syscall_dispatcher, mmap_replace
from angr.procedures.posix.sim_time import clock_gettime
import os
import re

PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

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
        print("No stack pointer recorded?")
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

def _parse_mod(mod):
    prot = 0
    if 'r' in mod:
        prot |= PROT_READ
    if 'w' in mod:
        prot |= PROT_WRITE
    if 'x' in mod:
        prot |= PROT_EXEC
    return prot

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
        mod = _parse_mod(mod)
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


def reverse_maps(maps):
    # TODO: rewrite
    reverse_map = {}
    for name, segs in maps.items():
        for seg in segs:
            for page in range(seg['start'], seg['end'], 0x1000):
                reverse_map[page>>12] = (name, seg['mod'])
    return reverse_map

def parse_maps_plus_reverse(maps):
    maps = parse_maps_plus(maps)
    return reverse_maps(maps)


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

def parse_maps_reverse_from_file(path, target = None, plus = False):
    with open(path, "r") as f:
        return parse_maps_plus_reverse(f.read())


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
def replace_stub(p, arch="amd64", test = False, syscall_info = None):
    """
    Replace project's all unsupported syscall to a stub, 
    which always return 0.
    XXX: Default syscall stub returns an unconstrained value, cause mutiple paths
    """
    
    sl = p.simos.syscall_library
    if test:
        for sysno, call_infos in syscall_info.items():
            # if sysno == 1:
            #     continue
            if sysno == 9:
                sd = dispatchers[sysno]
                sd.set_callinfo(call_infos)
                p.hook_symbol("mmap", sd)
                mmap_rep = mmap_replace(9, "mmap")
                mmap_rep.set_callinfo(call_infos)
                sl.procedures["mmap"] = mmap_rep
                continue
            if sysno in dispatchers:
                sd = dispatchers[sysno]
                sd.set_callinfo(call_infos)
                syscall_name = sl.syscall_number_mapping[arch][sysno]
                sl.procedures[syscall_name] = sd
                print("Setting up %s's syscall dispatcher." % syscall_name)
            else:
                print("sysno %d" % sysno)
                sd = syscall_dispatcher(sysno)
                sd.set_callinfo(call_infos)
                syscall_name = sl.syscall_number_mapping[arch][sysno]
                sl.procedures[syscall_name] = sd

        #     if sysno == 1:
        #         continue
        #     if sysno == 0:
        #         syscall_name = sl.syscall_number_mapping[arch][sysno]
        #         sl.procedures[syscall_name] = syscall_dispatcher(sysno, call_infos, modify = "rsi")
        #         continue
        #     if sysno == 2 or sysno == 41 or sysno == 43:
        #         syscall_name = sl.syscall_number_mapping[arch][sysno]
        #         sl.procedures[syscall_name] = sd =  syscall_dispatcher(sysno, call_infos)
                
        #         sd.add_posix_cb("""print(self.state.posix.open(hex(call_info["rbp"]+call_info["rdi"]), 3, preferred_fd = ret_info["rax"]))""")
        #         continue
        #     if sysno == 44 or sysno == 46:
        #         syscall_name = sl.syscall_number_mapping[arch][sysno]
        #         sl.procedures[syscall_name] = sd =  syscall_dispatcher(sysno, call_infos)
        #         sd.add_posix_cb("""fd = self.state.posix.get_fd(call_info["rdi"])\n""")
        #         sd.add_posix_cb("""print("write to %s" % fd)""")
        #         sd.add_posix_cb("""content = ret_info["mem_changes"][0]["content"]\n """)
        #         sd.add_posix_cb("""content = base64.b64decode(content)\n""")
        #         sd.add_posix_cb("""fd.write(content, ret_info["rax"])\n""")
        #         sd.add_posix_cb("""print("write %s" % content)""")

        #     syscall_name = sl.syscall_number_mapping[arch][sysno]
        #     sl.procedures[syscall_name] = syscall_dispatcher(sysno, call_infos)
        
        # replace other syscalls as always retuning 0
        for sysno, name in sl.syscall_number_mapping[arch].items():
            syscall = sl.get(sysno, arch, abi_list=[arch])
            if syscall.is_stub:
                #print("add %s" % name)
                sl.add(name, success_syscall_stub)
    else:
        for sysno, name in sl.syscall_number_mapping[arch].items():
            syscall = sl.get(sysno, arch, abi_list=[arch])
            if syscall.is_stub:
                #print("add %s" % name)
                sl.add(name, success_syscall_stub)
    if p.hook_symbol("clock_gettime", None) != None:
        print("hook clock_gettime")
        sd = dispatchers[228]
        # sd.set_callinfo(None)
        p.hook_symbol("clock_gettime", sd)

    
from binascii import unhexlify
def hex2str(h):
    h = hex(h)[2:]
    return unhexlify(h)



def parse_dumps(p, dump_file):
    result = {}
    with open(dump_file) as f:
        dumps = f.read()
        dumps = dumps.split('\n')[:-1]
        assert(len(dumps)&1 == 0)
        for i in range(0, len(dumps), 2):
            info = dumps[i]
            prot = info.split(' ')[1]
            mem = dumps[i+1]
            obj = info.split(' ')[-1].split('/')[-1]
            # if (obj != "[stack]") :
            #     continue
            addrs = info.split(' ')[0]
            start = int(addrs.split('-')[0], 16)
            end = int(addrs.split('-')[1], 16)
            if obj in result.keys():
                result[obj].append({"start": start, "size": end - start, "mem": base64.b64decode(mem), "prot": prot})
            else:
                result[obj] = [{"start": start, "size": end - start, "mem": base64.b64decode(mem), "prot": prot}]
            # result[start] = {"size":end-start, "mem":base64.b64decode(mem)}
    p.mem_dump = result


from elftools.elf.segments import Segment
from elftools.elf.dynamic import DynamicSegment

def recover_dump(state, mem_dump):
    index = 1
    for obj, dumps in mem_dump.items():
        for dump in dumps:
            if dump["prot"][1] == "w":
                state.memory.store(dump["start"], claripy.BVV(dump["mem"]), endness="Iend_BE")
                print("Recovering memory segment [%s]" % index)
                index += 1

    def _find_dynamic_segment(segments, file_addr, mems):
        for segment in segments:
            if isinstance(segment, DynamicSegment):
                header = segment.header
                seg_addr = header.p_vaddr + file_addr
                seg_size = header.p_memsz
                result = {"addr": seg_addr, "size": seg_size}
                for mem in mems:
                    start = mem["start"]
                    size = mem["size"]
                    if seg_addr >= start and seg_addr < start + size:
                        seg_mem = mem["mem"][seg_addr - start:seg_addr - start + seg_size]
                        result["mem"] = seg_mem
                        return result
        return None

    # recover PT_DYNAMIC segments
    elfs = state.project.elfs
    for obj, elf in elfs.items():
        if obj == state.project.target:
            continue
        # if "ld" in obj:
        #     continue
        segments = elf.segments
        dyn_result = _find_dynamic_segment(segments, elf.address, mem_dump[obj])
        if dyn_result:
            state.memory.store(dyn_result["addr"], claripy.BVV(dyn_result["mem"]), endness="Iend_BE")
            print("Recovering memory %s 's PT_DYNAMIC segment" % obj)


def parse_syscallinfo(path_to_syscallinfo):
    with open(path_to_syscallinfo, 'r') as f:
        content = f.read().split('\n')[:-1]
        result = {}
        for line in content:
            if line == "":
                continue
            tmp = eval(line)
            if tmp['sysno'] not in result:
                result[tmp['sysno']] = [tmp]
            else:
                result[tmp['sysno']].append(tmp)
        return result

def parse_lib_version(lib_opts):
    """
    a new field in malloc_state: 'have_fastchunks' (version>=2.27)
    tcache: (version>=2.26)
    """
    for lib in lib_opts:
        file = lib.split("/")[-1].split("-")
        if file[0] == "libc":
            if not os.access(lib, os.X_OK):
                os.system("chmod +x %s"%lib)
            libc_info = os.popen("%s | grep 'stable release version'"%lib).read()
            version = re.match(r".* release version ([0-9\.]*).*", libc_info).group(1)
            if version[-1] == '.':
                version = version[:-1]
            return version
    print("Cannot resolve lib's version!")
    return None

def version_compare(version1, version2):
    """
        lib version compare
        return :
        if version1 == version2 return 0;
        if version1 > version2 return 1;
        if version1 < version2 return -1.
    """
    version1_list = version1.split(".")
    version2_list = version2.split(".")
    length = max(len(version1_list), len(version2_list))
    for i in range(0, length):
        if i < len(version1_list):
            val1 = int(version1_list[i])
        else:
            val1 = 0
        if i < len(version2_list):
            val2 = int(version2_list[i])
        else:
            val2 = 0
        if val1 > val2:
            return 1
        if val1 < val2:
            return -1
    return 0
