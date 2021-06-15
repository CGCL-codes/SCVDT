import claripy
import angr
from structures import *
from parse_helpers import *

def get_malloc_state(state, addr = 0):
    """
    TODO: test this func
    get struct malloc_state from memory
    still we need the address of the struct
    """
    if state.project.heap_analysis.heapbase == 0:
        return None, None
    main_arena_addr = state.project.symbol_resolve.resolve("__malloc_hook") + 0x10

    # after 2.27 version, malloc_state struct in glibc is different
    if version_compare(state.project.lib_version, "2.27") >= 0:
        result = malloc_state_new()
    else:
        result = malloc_state()
    mem = state.memory.load(main_arena_addr, result.size)
    mem = mem.args[0].to_bytes(result.size, 'big')
    result.unpack(mem)
    if version_compare(state.project.lib_version, "2.27") >= 0:
        main_arena = malloc_state_new()
    else:
        main_arena = malloc_state()
    main_arena.unpack(mem)
    # if addr is in main thread's heap, addr shouldn't be on the same segment 
    # of malloc_state's address. But if it's on thread heap, addr should be on
    # the same seg with thread arena.
    if main_arena_addr == result.next:
        # we have only one arena! just return it
        return result, main_arena_addr
    else:
        # consider thread arena
        # TEST: multi-thread support haven't been tested!
        addr >>= 20
        while result.next != main_arena_addr and result.next != 0:
            # go to next arena
            temp_addr = result.next
            mem = state.memory.load(result.next, result.size)
            mem = mem.args[0].to_bytes(result.size, 'big')
            result.unpack(mem)
            if temp_addr >> 20 == addr:
                # we found it!
                return result, temp_addr
            else:
                continue
        # there's no match arena, so maybe given addr is on main thread's heap，
        # or it is an abused addr
        # we cannot determine...
        #print("Unable to find thread arena with addr %s!" % hex(addr))
        return main_arena, main_arena_addr

def single_list_iterate(state, link_head, ptr_offset): 
    """
    iterate a single list, until it meets 0 or a circle.
    Returns a list of all nodes the list have, including the head node,
    and if it is a circler list.

    :param state:       the state to get memory from
    :param link_head:   head of the list
    :ptr_offset:        offset of fd(next) ptr in the list's struct
    """
    circlar_node = 0
    bin_list = [link_head]
    link_head = state.memory.load(link_head + ptr_offset, 8, endness = 'Iend_LE').args[0]
    while link_head!=0:
        # a circle?
        if link_head in bin_list:
            circlar_node = link_head
            break
        bin_list.append(link_head)
        link_head = state.memory.load(link_head+ptr_offset, 8, endness = 'Iend_LE').args[0]
    return bin_list, circlar_node

def bin_fd_iterate(state, link_head):
    ptr_offset = 0x10
    return single_list_iterate(state, link_head, ptr_offset)

def bin_bk_iterate(state, link_head):
    ptr_offset = 0x18
    return single_list_iterate(state, link_head, ptr_offset)

def tcache_entries_iterate(state, link_head):
    ptr_offset = 0
    return single_list_iterate(state, link_head, ptr_offset)

def align16(value):
    return (value>>4)<<4

def _get_one_bin(state, link_head, head_addr = 0, is_bk = 0, is_tcache = 0):
    circlar = 0
    chks = []
    nodes = []
    if link_head:
        # get all chunk's addr
        if is_tcache:
            nodes, circlar = tcache_entries_iterate(state, link_head)
            for node in nodes:
                chk_size = state.memory.load(node - 8, 8, endness = "Iend_LE").args[0]
                chk = (node-0x10, chk_size)
                chks.append(chk)
        else:
            if is_bk:
                nodes, circlar = bin_bk_iterate(state, link_head)
                #print(nodes)
            else:
                nodes, circlar = bin_fd_iterate(state, link_head)
            # also get size info now
            for node in nodes:
                if node == head_addr - 0x10 - 8*is_bk:
                    chk_size = 0
                else:
                    chk_size = state.memory.load(node+8, 8, endness = "Iend_LE").args[0]
                chk = (node, chk_size)
                chks.append(chk)
    return chks, circlar, nodes

def ptr_check(ptr, reverse_maps, state=None):
    page = ptr >> 12
    prot = -1
    if state:
        try:
            prot = state.memory.permissions(ptr)
            return prot.args[0]
        except angr.errors.SimMemoryMissingError:
            return -1
    else:
        if page in reverse_maps:
            return reverse_maps[page]
        else:
            return -1

def ptr_lookup(ptr, reverse_maps, state=None):
    prot = ptr_check(ptr, reverse_maps, state)
    if prot == -1:
        return -1
    else:
        page = ptr >> 12
        if page in reverse_maps:
            return reverse_maps[page]
        else:
            return None

def printable_fastbin_entry(nodes, circlar=0):
    result = ""
    for i in range(0, len(nodes)):
        if i == len(nodes)-1:
            result += "[0x%x]" % nodes[i]
            break
        result += "[0x%x]" % nodes[i] + " -> "
    if circlar:
        result += " <- " + hex(circlar) + "(corrupted)"
    else:
        result += ' -> 0\n'
    return result

def printable_bin_entry(is_corrupted, fd_nodes, fd_circlar, bk_nodes, bk_circlar, size = 0):
    """
    print the bins list ptr content
    """
    def printable_list(nodes):
        list_result = ""
        for i in range(0, len(nodes)):
            if i == len(nodes)-1:
                list_result += "[%s]" % hex(nodes[i])
                break
            list_result += "[%s] -> " % hex(nodes[i])
        return list_result

    result = ""
    if size:
        result += "%s " % hex(size)

    if is_corrupted:
        result += "[corrupted]\n"
        result += "FD: "
        result += printable_list(fd_nodes)
        result += " <- " + hex(fd_circlar)
        result += '\n'
        result += "BK: "
        result += printable_list(bk_nodes)
        result += " <- " + hex(bk_circlar)
    else:
        result += "all: "
        result += printable_list(fd_nodes)
        result += " <- " + hex(fd_circlar)
    return result

def is_bin_corrupted(fd_nodes, bk_nodes):
    """
    judge whether the bins is legal
    """
    if len(fd_nodes) != len(bk_nodes):
        return True
    length = len(fd_nodes)
    if length == 0:
        return False
    if fd_nodes[length-1] != bk_nodes[length-1]:
        return True
    for i in range(0, length-1):
        if fd_nodes[i] != bk_nodes[length-2-i]:
            return True
    return False

def largebins_size_64(index):
    """
    get largebins minsize by index
    """
    index &= 0xfe
    index >>= 1
    if index >= 63 and index <= 94:
        return 1024 + (index-63)*64
    elif index <= 110:
        return 3072 + (index-95)*512
    elif index <= 118:
        return 11264 + (index-111)*4096
    elif index <= 122:
        return 44032 + (index-119)*32768
    elif index <= 124:
        return 175104 + (index-123)*262144
    else:
        return 0

class Arena(object):
    def __init__(self, state, addr = 0):
        self.fastbin = [ 0 for i in range(10)]
        self.fastbin_c = [ 0 for i in range(10)]
        self.fastbin_nodes = [0 for i in range(10)]
        self.bins = [ 0 for i in range(254)]
        self.bins_c = [ 0 for i in range(254)]
        self.bins_addr = [0 for i in range(254)]
        self.bins_nodes = [0 for i in range(254)]
        self.unsorted_bin = 0
        self.unsorted_bin_c = 0
        self.unsorted_bin_nodes = 0
        self.arena = 0
        self.addr = 0
        self.state = state
        self.get_arena(addr)
        # heap is not initial
        if self.arena is None:
            return
        self.get_bins()
        self.get_fastbin()

    def get_arena(self, addr = 0):
        state = self.state
        self.arena, self.addr = get_malloc_state(state, addr)
        if self.arena is None:
            return
        if version_compare(state.project.lib_version, "2.27") >= 0:
            self.bins_addr = range(self.addr+0x70, self.addr+0x70+8*254, 8)
        else:
            self.bins_addr = range(self.addr+0x68, self.addr+0x68+8*254, 8)

    def get_fastbin(self):
        state = self.state
        arena = self.arena
        assert(arena)
        for i in range(0, len(arena.fastbinsY)):
            link_head = arena.fastbinsY[i]
            chks, circlar, nodes = _get_one_bin(state, link_head)
            self.fastbin[i] = chks
            self.fastbin_c[i] = circlar
            self.fastbin_nodes[i] = nodes
        
    def get_bins(self):
        state = self.state
        arena = self.arena
        assert(arena)
        for i in range(0, len(arena.bins), 2):
            fd = arena.bins[i]
            fd_addr = self.bins_addr[i]
            bk = arena.bins[i+1]
            bk_addr = self.bins_addr[i+1]
            chks, circlar, nodes = _get_one_bin(state, fd, head_addr=fd_addr)
            self.bins[i] = chks
            self.bins_c[i] = circlar
            self.bins_nodes[i] = nodes
            chks, circlar, nodes = _get_one_bin(state, bk, head_addr=bk_addr, is_bk=1)
            self.bins[i+1] = chks
            self.bins_c[i+1] = circlar
            self.bins_nodes[i+1] = nodes
        self.unsorted_bin = self.bins[:2]
        self.unsorted_bin_c = self.bins_c[:2]
        self.unsorted_bin_nodes = self.bins_nodes[:2]

    def get_all_chunks(self):
        chks = []
        for entry in self.fastbin:
            if entry:
                for i in entry:
                    chks.append(i)
        for entry in self.bins:
            if entry:
                for i in entry:
                    if i[1] != 0:
                        chks.append(i)
        chks = set(chks)
        return list(chks)
    
    def fastbin_check(self, idx):
        nodes = self.fastbin_nodes[idx]
        circlar = self.fastbin_c[idx]

        for node in nodes:
            owner = ptr_lookup(node, self.state.project.reverse_maps, self.state)
            if owner == -1:
                print("Found unmapped address in fastbin.")
            elif owner:
                if owner[0]:
                    print("Found fastbin points to %s !" % owner[0])
        if circlar:
            print("fastbin[%d] corrupted!" % idx)
            # TODO: show this bin
            # print(printable_fastbin_entry(nodes, circlar))
    
    def bin_check(self, idx):
        assert(idx >= 0 and idx <254)
        idx &= 0xfe
        fd_nodes = self.bins_nodes[idx]
        bk_nodes = self.bins_nodes[idx+1]
        fd_circlar = self.bins_c[idx]
        bk_circlar = self.bins_c[idx+1]
        # bk_list = bk_nodes[::-1]
        fd_len = len(fd_nodes)
        bk_len = len(bk_nodes)
        for fd_node in fd_nodes:
            owner = ptr_lookup(fd_node, self.state.project.reverse_maps, self.state)
            if owner == -1:
                print("Found unmapped address in bins")
            elif owner:
                if owner[0]:
                    print("Found bin points to %s !" % owner[0])
        for bk_node in bk_nodes:
            owner = ptr_lookup(bk_node, self.state.project.reverse_maps, self.state)
            if owner == -1:
                print("Found unmapped address in bins")
            elif owner:
                if owner[0]:
                    print("Found bin points to %s !" % owner[0])
        # show_bin = 0
        # if fd_len != bk_len:
        #     print("Bin[%d] corrupted!" % idx)
        #     show_bin = 1
        # for i in range(min(fd_len, bk_len)):
        #     if fd_nodes[i] != bk_nodes[i]:
        #         show_bin = 1
        is_corrupted = False
        if is_bin_corrupted(fd_nodes, bk_nodes):
            # print("Bin[%d] corrupted!" % idx)
            is_corrupted = True
        if is_corrupted:
            # print(printable_bin_entry(is_corrupted, fd_nodes, fd_circlar, bk_nodes, bk_circlar))
            pass

    def do_check(self):
        for i in range(0, len(self.fastbin)):
            if len(self.fastbin[i]) > 0:
                self.fastbin_check(i)
        for i in range(0, len(self.bins), 2):
            if len(self.bins[i]) > 0:
                self.bin_check(i)

    def output_fastbins(self):
        result_head = "fastbinsY:\n"
        result = ""
        size = 0x20
        for i in range(0, len(self.fastbin)):
            if len(self.fastbin_nodes[i]) == 0:
                size += 0x10
                continue
            result += "%s:" % hex(size)
            result += printable_fastbin_entry(self.fastbin_nodes[i], self.fastbin_c[i])
            size += 0x10
        if result == "":
            result += "empty"
        return result_head + result

    def output_unsorted_bin(self):
        result_head = "unsortedbin:\n"
        result = ""
        fd_nodes = self.bins_nodes[0]
        bk_nodes = self.bins_nodes[1]
        fd_circlar = self.bins_c[0]
        bk_circlar = self.bins_c[1]
        if (len(fd_nodes) == 1 and fd_nodes[0] == fd_circlar) or len(fd_nodes) == 0:
            if (len(bk_nodes) == 1 and bk_nodes[0] == bk_circlar) or len(bk_nodes) == 0:
                return result_head + "empty"
        result += printable_bin_entry(is_bin_corrupted(fd_nodes, bk_nodes), fd_nodes, fd_circlar, bk_nodes, bk_circlar)
        if result == "":
            result += "empty"
        return result_head + result

    def output_small_bins(self):
        result_head = "smallbins:\n"
        result = ""
        for i in range(2, 125, 2):
            fd_nodes = self.bins_nodes[i]
            bk_nodes = self.bins_nodes[i+1]
            fd_circlar = self.bins_c[i]
            bk_circlar = self.bins_c[i+1]
            if (len(fd_nodes) == 1 and fd_nodes[0] == fd_circlar) or len(fd_nodes) == 0:
                if (len(bk_nodes) == 1 and bk_nodes[0] == bk_circlar) or len(bk_nodes) == 0:
                    continue
            result += printable_bin_entry(is_bin_corrupted(fd_nodes, bk_nodes), fd_nodes, fd_circlar, bk_nodes, \
                                          bk_circlar, ((i>>1)+1)<<4)
            result += "\n"
        if result == "":
            result += "empty"
        if result[-1] == "\n":
            result = result[:-1]
        return result_head + result

    def output_large_bins(self):
        result_head = "largebins:\n"
        result = ""
        for i in range(126, len(self.bins_nodes), 2):
            fd_nodes = self.bins_nodes[i]
            bk_nodes = self.bins_nodes[i+1]
            fd_circlar = self.bins_c[i]
            bk_circlar = self.bins_c[i+1]
            if (len(fd_nodes) == 1 and fd_nodes[0] == fd_circlar) or len(fd_nodes) == 0:
                if (len(bk_nodes) == 1 and bk_nodes[0] == bk_circlar) or len(bk_nodes) == 0:
                    continue
            result += printable_bin_entry(is_bin_corrupted(fd_nodes, bk_nodes), fd_nodes, fd_circlar, bk_nodes, \
                                          bk_circlar, largebins_size_64(i))
            result += "\n"
        if result == "":
            result += "empty"
        if result[-1] == "\n":
            result = result[:-1]
        return result_head + result

    def output_all_bins(self):
        if self.arena is None:
            return None
        result = ""
        result += self.output_fastbins() + "\n"
        result += self.output_unsorted_bin() + "\n"
        result += self.output_small_bins() + "\n"
        result += self.output_large_bins()
        return result

 # TODO: rewrite   
def fastbin_check(state, malloc_state, arena_addr):
    """
    fastbin is a single list, which shouldn't contain circle.

    """
    #output = ""
    for link_head in malloc_state.fastbinsY:
        if link_head == 0:
            continue
        nodes, circlar = bin_fd_iterate(state, link_head)
        for node in nodes:
            owner = ptr_lookup(node, state.project.reverse_maps, state)
            if owner == -1:
                print("Found unmapped address in fastbin.")
            elif owner:
                if owner[0]:
                    print("Found fastbin points to %s !" % owner[0])
        if circlar:
            print("Found corrupted fastbin!")
        print(printable_fastbin_entry(nodes, circlar))

#TODO: rewrite
def bin_check(state, malloc_state, arena_addr):
    # seems we have to get arena address...
    arena_size = malloc_state.size
    for i in range(0, len(malloc_state.bins), 2):
        fd, bk = malloc_state.bins[i:i+2]
        fd_nodes, fd_circlar = bin_fd_iterate(state, fd)
        bk_nodes, bk_circlar = bin_bk_iterate(state, bk)
        if len(fd_nodes) == 1 and fd_nodes[0] == fd_circlar:
           if len(bk_nodes) == 1 and bk_nodes[0] == bk_circlar:
               continue
        is_corrupted = False
        if is_bin_corrupted(fd_nodes, bk_nodes):
            print("bins has been borken!")
            is_corrupted = True
        print(printable_bin_entry(is_corrupted, fd_nodes, fd_circlar, bk_nodes, bk_circlar))
    # print(printable_bin_entry(fd_nodes + [fd_circlar], bk_nodes + [bk_circlar]))
    pass

def unsortedbin_check(state, malloc_state, arena_addr):
    pass


"""
tcache struct analysis
"""
def get_tcache_struct(state, addr = 0):
    """
    TODO: test this func
    get struct tcache_perthread_struct from memory
    still we need the address of the struct
    """
    # before 2.26 version, doesn't need to analysis tcache struct
    if version_compare(state.project.lib_version, "2.26") < 0:
        return None, None
    # if heap is not inited, doesn't neet to analysis tcache struct
    if state.project.heap_analysis.tcache_address == 0:
        return None, None

    tcache_addr = state.project.heap_analysis.tcache_address

    # after 2.30 version, tcache_perthread_struct is different
    if version_compare(state.project.lib_version, "2.30") >= 0:
        result = tcache_perthread_struct_new()
    else:
        result = tcache_perthread_struct()

    mem = state.memory.load(tcache_addr, result.size)
    mem = mem.args[0].to_bytes(result.size, 'big')
    result.unpack(mem)
    if version_compare(state.project.lib_version, "2.30") >= 0:
        tcache = tcache_perthread_struct_new()
    else:
        tcache = tcache_perthread_struct()
    tcache.unpack(mem)

    return tcache, tcache_addr

def printable_tcache_entries(nodes, circlar, size, count):
    result = "[%s][ %s]" % (hex(size), count)
    for node in nodes:
        result += "0x%x" % node + " -> "
    if circlar == 0:
        result += "0"
    else:
        result += " <- %s (corrupted)" % hex(circlar)
    return result

class Tcache(object):
    def __init__(self, state, addr=0):
        self.state = state
        self.get_tcache(addr)
        assert (self.tcache != 0)
        if self.tcache is None or self.addr is None:
            return
        self.entries_bins = [0 for i in range(64)]
        self.entries_bins_c = [0 for i in range(64)]
        self.entries_bins_nodes = [0 for i in range(64)]
        self.get_counts()
        self.get_entries()
        self.get_entries_bins()

    def get_tcache(self, addr):
        state = self.state
        self.tcache, self.addr = get_tcache_struct(state, addr)

    def get_counts(self):
        self.counts = self.tcache.counts

    def get_entries(self):
        self.entries = self.tcache.entries

    def get_entries_bins(self):
        for i in range(0, len(self.counts)):
            if self.counts[i] > 0:
                chks, circlar, nodes = _get_one_bin(self.state, self.entries[i], is_tcache=1)
                self.entries_bins[i] = chks
                self.entries_bins_c[i] = circlar
                self.entries_bins_nodes[i] = nodes

    def get_all_chunks(self):
        chks = []
        for i in range(0, len(self.counts)):
            if self.counts[i] > 0:
                for entry in self.entries_bins[i]:
                    chks.append(entry)
        return chks

    def do_check(self):
        pass

    def output_tcache_bins(self):
        if self.tcache is None:
            return None
        result_head = "tcachebins\n"
        result = ""
        for i in range(0, len(self.counts)):
            if self.counts[i] > 0:
                result += printable_tcache_entries(self.entries_bins_nodes[i], self.entries_bins_c[i], 0x20 + 0x10 * i, self.counts[i])
                result += "\n"
        if result == "":
            result += "empty"
        if result[-1] == "\n":
            result = result[:-1]
        return result_head + result