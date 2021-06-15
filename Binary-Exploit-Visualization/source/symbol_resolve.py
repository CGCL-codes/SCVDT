import claripy

# 'resolve' symbol name from symbol addr
class symbol_resolve(object):
    """
    DO resolve job.
    TODO: rewrite
    """
    def __init__(self, project):
        self.project = project

    def find_obj(self, addr):
        maps = self.project.maps
        for obj, segs in maps.items():
            for seg in segs:
                if addr >= seg["start"] and addr <=seg["end"]:
                    return obj
                else:
                    continue
        
        #print("Cannot find symbol of addr %s." % hex(addr))
        return None

    def _syscall_reverse_resolve(self, addr):
        if self.project.simos.is_syscall_addr(addr):
            syscall = self.project.simos.syscall_from_addr(addr)
            return syscall.display_name + "_syscall"
        else:
            return None

    def resolve(self, name):
        """
        Resolve symbol address by name.
        Returns (symbol address, object name of the address)
        There maybe symbols with same names in different libs, specify the obj_name to
        get the specific address.
        """
        return self.project.loader.find_symbol(name).rebased_addr

    def reverse_resolve(self, addr, must_plus = False):
        """
        Resolve symbol name by symbol address. TODO: should be replace by using dwarf
        Returns (symbol name, offset of the found symbol, object name which includes
        the symbol).
        If not found, return None.
        """
        if isinstance(addr, claripy.ast.bv.BV):
            addr = addr.args[0]
        if not isinstance(addr, int):
            raise TypeError('Addr cannot convert to int!')
        # first find which object the addr belongs to
        found_obj = self.find_obj(addr)
        if not found_obj:
            name = self._syscall_reverse_resolve(addr)
            if name:
                return name, 0, "kernel space"
            else:
                return None
        
        # now try to find the symbol name
        found_obj = found_obj.split('/')[-1]
        if found_obj not in self.project.elfs:
            return None
        obj = self.project.elfs[found_obj.split('/')[-1]]
        # index the dict with addr
        symbols = {v:k for k, v in obj.symbols.items()}
        addrs = [ i for i in symbols]

        min_offset = 0xffffffff
        nearest_addr = -1
        for i in symbols:
            if must_plus and i > addr:
                continue
            offset = abs(i - addr)
            if offset < min_offset:
                min_offset = offset
                nearest_addr = i

        min_offset = addr - nearest_addr
        if nearest_addr == -1:
            return "sub_%x" % addr, 0, found_obj
        name = symbols[nearest_addr]
        if "plt." in name and abs(min_offset)> 0x100:
            return "sub_%x" % addr, 0, found_obj
        return name, min_offset, found_obj

