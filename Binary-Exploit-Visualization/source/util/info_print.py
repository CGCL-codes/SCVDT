import angr

PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

def printable_callstack(state):
    cs = state.callstack
    frame_no = 1
    now = state.regs.rip.args[0]
    symbol = state.project.symbol_resolve.reverse_resolve(now, must_plus = True)
    result = "\nFrame\t0:\t%#018x\t\t" % (now)
    if symbol:
        if '__gmon_start__'  in symbol[0]:
            symbol = list(symbol)   
            symbol[0] = 'sub_%x'% now
            symbol[1] = 0
        if symbol[1]:
            result += "%s%+d " % (symbol[0], symbol[1])
        else:
            result += "%s " % symbol[0]
    result = result.ljust(65, " ")
    result += "sp: %#018x\n" % state.regs.rsp.args[0]

    for frame in cs:
        line = ""
        if not frame.func_addr:
            return result
        line += "Frame\t%d:\t%#018x\t\t" % (frame_no, frame.ret_addr)
        symbol  = state.project.symbol_resolve.reverse_resolve(frame.ret_addr, must_plus = True)
        if symbol:
            if '__gmon_start__'  in symbol[0]:
                symbol = list(symbol)   
                symbol[0] = 'sub_%x'% frame.call_site_addr
                symbol[1] = 0
            if symbol[1]:
                line += "%s%+d " % (symbol[0], symbol[1])
            else:
                line += "%s " % symbol[0]
        
        line = line.ljust(64, " ")
        line += "sp: %#018x\n" % frame.stack_ptr
        result += line
        frame_no += 1

    return result            


class stack_frame(object):
    def __init__(self, addr, bp, symbol = None, frame_no = -1):
        self.addr = addr
        self.bp = bp
        self.symbol = symbol
        self.next = None
        self.no = frame_no
    
    def __str__(self):
        result = "Frame "
        if self.no != -1:
            result += "%d: " % self.no
        else:
            result += ": "
        
        result += "%#018x" % self.addr
        if self.symbol:
            name = self.symbol[0]
            offset = self.symbol[1]
            if "__gmon_start__" in name:
                name = "sub_%x" % (self.addr+offset)
                offset = 0

            result += "\tin %s" % name
            if offset != 0:
                result += "%+d" % offset
            result = result.ljust(64, " ")
        else:
            result = result.ljust(68, " ")
        result += "bp: 0x%x\n" % self.bp
            
        return result

def find_add_sp(state, last_ret):
    ret_found = 0
    result = 0
    bb = state.block(last_ret)
    while not ret_found:
        for insn in bb.capstone.insns:
            print("%s\t%s"%(insn.insn.insn_name(), insn.insn.op_str))
            if insn.insn.insn_name() == "ret":
                return result
            if insn.insn.insn_name() == "add":
                if "rsp" in insn.insn.op_str:
                    opvalue = insn.insn.op_str.split(", ")[-1]
                    if "0x" in opvalue:
                        opvalue = int(opvalue, 16)
                    else:
                        if not opvalue.isnumeric():
                            continue
                        opvalue = int(opvalue)
                    result += opvalue
            if insn.insn.insn_name() == "pop":
                result += 8
            if insn.insn.insn_name() == "push":
                result -= 8
        bb = state.block(bb.addr+bb.size)

def stack_backtrace(state, depth = 'Max'):
    """
    Helper func to get stack backtrace.
    Do the same work as gdb's bt.

    :param state:   state to do bt
    :param depth:   bt depth
    """
    # gdb's backtrace records present rip in frame0, do the same with gdb
    symbol = state.project.symbol_resolve.reverse_resolve(state.regs.rip.args[0], must_plus = True)
    result = [stack_frame(state.regs.rip.args[0], state.regs.rbp.args[0], symbol, 0)]
    bp = state.regs.rbp.args[0]
    sp = state.regs.rsp.args[0]
    frame_num = 16 if depth=='Max' else depth
    no = 0
    use_sp = 1

    while frame_num:
        no += 1
        frame_num -= 1
        # first check sp(only leave funcs use sp to index the stack)
        if use_sp:
            ret_addr = state.memory.load(sp, 8, endness = 'Iend_LE').args[0]
            if ret_addr < state.project.loader.min_addr or ret_addr > state.project.loader.max_addr:
                use_sp = 0
                # then goto backtrace use bp
            else:
                use_sp = 0
                symbol = state.project.symbol_resolve.reverse_resolve(ret_addr, must_plus = True)
                # XXX: use sp to represent bp?
                frame = stack_frame(ret_addr, sp, symbol, no)
                bp = state.memory.load(sp-0x10, 8, endness = 'Iend_LE').args[0]
                #print(hex(bp))
                result.append(frame)
                continue

        # then use bp to backtrace
        ret_addr = state.memory.load(bp+8, 8, endness = 'Iend_LE').args[0]
        bp = state.memory.load(bp, 8, endness = 'Iend_LE').args[0]
        symbol = state.project.symbol_resolve.reverse_resolve(ret_addr, must_plus = True)
        frame = stack_frame(ret_addr, bp, symbol, no)

        result.append(frame)

        if ret_addr < state.project.loader.min_addr or ret_addr > state.project.loader.max_addr:
            return result
        if bp == 0 or bp >= 0x7fffffffffff:
            return result
    return result





def printable_backtrace(bt):
    """
    format stack_backtrace's result to a str

    :param bt: result of stack_backtrace
    """
    result = "\n"
    for i in bt:
        result += str(i)
    return result


def fetch_str(state, addr):
    try:
        prots = state.memory.permissions(addr)
    except :
        return ""
    prots = prots.args[0]
    result = ""
    is_str = 1
    # TODO: move prots definition to other place
    if not (prots & PROT_READ):
        return ""
    while is_str:
        m = state.memory.load(addr, 8)
        assert(m.concrete)
        m = m.args[0]
        addr += 8

        for i in range(8):
            c = (m >> (7-i)*8) & 0xff
            if c > 126 or c < 32:
                is_str = False
                break
            else:
                result += chr(c)

    return result

def fetch_args_array(state, args_addr):
    try:
        prots = state.memory.permissions(args_addr)
    except :
        return None
    prots = prots.args[0]
    array = []
    is_end = 1
    if not (prots & PROT_READ):
        return None
    while is_end:
        str_ptr = state.memory.load(args_addr, 8, endness = 'Iend_LE')
        assert(str_ptr.concrete)
        str_ptr = str_ptr.args[0]
        args_addr += 8
        if str_ptr == 0:
            is_end = 0
            continue
        array.append(fetch_str(state, str_ptr))
    return array

from termcolor import colored
def printable_memory(state, start, size, warn_pos = 0, warn_size = 0, info_pos = 0, info_size = 0):
    result = "\n"
    # align
    start = ((start >>4) << 4)
    # print(size)
    size = ((size >>4) <<4) + 0x10
    # print("%s %s" % (hex(start), hex(size)))
    endl = -1
    warn = 0
    for addr in range(start, start+size, 8):
        mem = state.memory.load(addr, 8, endness = "Iend_LE")
        assert(mem.concrete)
        mem = mem.args[0]
        if endl:
            result += "%s| " %(hex(addr))
            endl = ~endl
        else:
            result += '  ' 
            endl = ~endl
        mem = "%016x" % mem
        colored_mem = ["" for i in range(8)]
        j = 0
        for i in range(14, -2, -2):
            bt = mem[i:i+2]
            if addr + j in range(warn_pos, warn_pos+warn_size):
                bt = colored(bt, 'red')
            if addr + j in range(info_pos, info_pos+info_size):
                bt = colored(bt, 'yellow')
            colored_mem[7-j] = bt
            j += 1

        result += "".join(colored_mem) 
        if endl:
            result += '\n'
    return result