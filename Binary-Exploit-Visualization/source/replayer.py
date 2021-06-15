# -*- coding:utf-8 -*-
import networkx
LOGGER_PROMPT = b"$LOGGER$"
from parse_helpers import *
from exploited_state_hook import exploited_execve
from pwnlib.elf.elf import ELF
from symbol_resolve import symbol_resolve

from util.rep_pack import rep_pack
from report.generate_html import generate_report
from syscall_dispatcher import reset_dispatchers
from function_replace import *

from analysis import visualize_analysis
from util.common import *
from angrutils import plot_cfg

#p = angr.Project("./aa", main_opts = main_opts, lib_opts = lib_opts,auto_load_libs=True, use_sim_procedures=False )
#state = p.factory.entry_state(mode="tracing", stdin=sim_file)


class Replayer(angr.project.Project):
    """
    Do the replay job.
    XXX: all unsupported syscall will always return 0

    :param binary_path:      path to the target binary_path
    :param log_path:    path to logged input
    :param map_path:    path to the memory map recorded at entry point

    :ivar exploited_state:  the final state when target it pwned
    :ivar input:        angr.SimPackets，contains the recorded input

    :ivar cfg:          target's cfg, with library func explored
    :ivar cfg_recorded: target's cfg, recorded during the exploit
    :ivar cfg_sequence: target's control flow sequence during the exploit

    :ivar hooked_addr:  list of addr been hooked
    """
    def __init__(self, binary_path, log_path, map_path, lib_version = None, new_syscall = False):
        assert(isinstance(binary_path, str))
        assert(isinstance(log_path, str))
        assert(isinstance(map_path, str))
        self.__binary_path = binary_path
        self.__log_path = log_path
        self.__map_path = map_path
        self.test = new_syscall
        self.from_syscall = 0

        
        target_name = binary_path.split(r"/")[-1]
        self.target = target_name

        main_opts, lib_opts, bp = parse_maps_from_file(map_path, target_name)

        # use pwnlib's ELF to save all objects
        # XXX: angr.loader has loaded all objects...
        self.elfs = {self.target:ELF(binary_path, checksec=False)}
        self.elfs[self.target].address = main_opts["base_addr"]
        for k, v in lib_opts.items():
            f = ELF(k, checksec=False)
            # TEST: only use filename, not path?
            k = k.split("/")[-1]
            f.address = v["base_addr"]
            self.elfs[k] = f

        self.lib_version = lib_version if lib_version is not None else parse_lib_version(lib_opts)

        # bug fix...
        tmp = {}
        for i in lib_opts:
            tmp[i.split('/')[-1]] = lib_opts[i]
        lib_opts = tmp


        self.maps = parse_maps_from_file(map_path, plus = True)
        self.mem_dump = 0
        self.reverse_maps = reverse_maps(self.maps)
        self.brk_address = []
        if "heap" in self.maps.keys():
            self.brk_address.append(self.maps["heap"][0]["start"])
            self.brk_address.append(self.maps["heap"][0]["end"])

        #report log is in the same directory
        self.report_log_path = os.getcwd()
        self.report_logger = 0

        self.cfg = 0
        self.cfg_recorded = 0
        self.cfg_sequence = 0
        self.bbl_len = 0

        self.hooked_addr = []

        self._main_opts = main_opts
        self._lib_opts = lib_opts
        self._bp = bp
        self.exploited_state = 0
        self.exploited_state_method = None
        self.end_timestamp = 0
        self.enabled_anas = {}


        # construct the project, load objects with recorded base addr
        skip_libs = ['mmap_dump.so']
        force_load_libs = []
        for i in self.maps:
            if not os.access(i, os.X_OK):
                continue
            if i.split('/')[-1] in skip_libs:
                continue
            else:
                force_load_libs.append(i)

        super().__init__(binary_path, main_opts = main_opts, lib_opts = lib_opts, \
            auto_load_libs=False, use_sim_procedures=False , preload_libs = force_load_libs)
        # super().__init__(binary_path, main_opts=main_opts, \
        #                  auto_load_libs=False, use_sim_procedures=False)

        # replace unsupported syscall
        if self.test:
            syscall_info = parse_syscallinfo(log_path)
            replace_stub(self, test=True, syscall_info = syscall_info)
            parse_dumps(self, map_path+".dump")
        else:
            replace_stub(self)
            self.input = parse_log_from_file(log_path)
        self.fake_fs = [{"path": "", "type": "stdin", "content":[], "last_fd":0},
                        {"path": "", "type": "stdout", "content":[], "last_fd":1},
                        {"path": "", "type": "stderr", "content":[], "last_fd":2},
        ]
        self.fdset = {0:0, 1:1, 2:2}


        # do some steps as test
        # simgr = self.get_simgr()
        # simgr.step()

        # FIXME: set the hook to detect pwned state??
        self.set_exploited_syscall("execve", exploited_execve())

        # TEST: set heap analysis
        self.symbol_resolve = symbol_resolve(self)

        # TEST: serialize the project
        self.packer = rep_pack(self.__binary_path, self.__log_path, self.__map_path)

        # TEST: functions hook to replace
        self.replace_function()

    
    def get_entry_state(self):
        """
        Returns the state at entry point, with stdin set to recorded input
        """
        if not self.test:
            state = self.factory.entry_state(mode="tracing", stdin=self.input)
        else:
            state = self.factory.entry_state(mode="tracing")

        state.regs.rsp = self._bp

        if self.mem_dump:
            print("Recovering memory snapshot.")
            recover_dump(state, self.mem_dump)      
        reset_dispatchers()  
        return state

    def get_simgr(self, from_state = None):
        """
        Returns the simgr at specific/entry state

        :param from_state:  start state of simgr
        """
        if from_state:
            return self.factory.simgr(from_state)
        else:
            return self.factory.simgr(self.get_entry_state())

    def navigate_to(self, addr, from_state = None):
        """
        Returns a state, which runs to specific addr

        :param addr:        target addr
        :param from_state:  start of simgr, default the entry_state
        """
        if from_state:
            state = from_state
        else:
            state = self.get_entry_state()

        simgr = self.factory.simgr(state)

        simgr.explore(find = addr)
        if simgr.stashes['found']:
            return simgr.found[0]
        return None

    def do_track(self):
        """
        Tracks control flow changes during the exploit.
        """
        simgr = self.get_simgr()
        # simgr.active[0].options.discard("UNICORN")
        # simgr.active[0].options.discard("COPY_STATES")
        # simgr.active[0].options.add("SUPPORT_FLOATING_POINT")
        simgr.active[0] = set_state_options(simgr.active[0])
        simgr.run()
        # list = simgr.errored[0].state.history.bbl_addrs.hardcopy
        # content = ""
        # with open("addrs", "w") as f:
        #     for aaddr in list:
        #         content += hex(aaddr) + "\n"
        #     f.write(content)
        #     f.close()
        if len(simgr.deadended) <= 0:
            print("replay failed！")
            exit(-1)
        state = simgr.deadended[0]
        self.cfg_sequence = list(state.history.bbl_addrs)
        self.cfg_recorded = networkx.Graph()

        # no history?
        assert(len(self.cfg_sequence) > 1)

        last_addr = self.cfg_sequence[0]
        for addr in self.cfg_sequence[1:]:
            self.cfg_recorded.add_edge(last_addr, addr)
            last_addr = addr

    def generate_cfg(self, starts=[], fromstate=None):
        """
        Generates the original cfg.
        XXX: Lib funcs are included.
        """
        if fromstate is None and len(starts) == 0:
            self.cfg = self.analyses.CFGFast(force_complete_scan=False)
            return self.cfg
        # print("start cfg generate")
        # cfg = self.analyses.CFGEmulated(call_depth=1, starts=starts, initial_state=self.get_entry_state())
        # plot_cfg(cfg, "cfgtest", asminst=True, remove_imports=True, remove_path_terminator=True)
        # print("generate success")


    def set_exploited_syscall(self, name, procedure):
        """
        Set a syscall sim_procedure. During replay, it will check the params passed to it,
        to decide if target is pwned.
        exploited_state will be set.

        :param name:        syscall name
        :param procedure:   sim procedure to do the work
        """
        # don't set project now, or deepcopy will fail.
        #procedure.project = self
        self.simos.syscall_library.procedures[name] = procedure

    def set_exploited_func(self, addr, hook_func):
        """
        Set a syscall sim_procedure. During replay, it will check the params passed to it,
        to decide if target is pwned.
        exploited_state will be set.

        :param addr:        addr to hook
        :param hook_func:   func to use
        """
        self.hook(addr, hook_func(self))
        self.hooked_addr.append(addr)

    def enable_analysis(self, anas):
        for name in anas:
            if name in visualize_analysis:
                ana = visualize_analysis[name]
                inited_ana = ana(self)
                print("%s enabled." % name)
                dirty_s = "self.%s=inited_ana" % name
                exec(dirty_s)
                self.enabled_anas[name] = inited_ana

    def do_analysis(self):
        analysis_file = os.path.join(self.report_log_path, "analysis.log")
        if os.path.isfile(analysis_file):
            os.remove(analysis_file)
        for ana_name in self.enabled_anas:
            exec("self.%s.do_analysis()" % ana_name)

    def generate_report(self):
        generate_report(self.__binary_path, self.__map_path, analysis_path="./analysis.log" )

    def replace_function(self):
        # some functions can not be supported by pyvex, such as funcs used sse4 ins
        # we can replace them by hook function
        # pass
        init_function_replace(self)




    
