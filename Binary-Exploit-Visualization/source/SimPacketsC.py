import angr
import claripy
import logging
import itertools

from angr.storage.memory_object import SimMemoryObject
from angr.state_plugins.plugin import SimStatePlugin
from angr.state_plugins.sim_action_object import SimActionObject
from angr import sim_options
from angr.errors import *



class SimPacketsC(angr.SimPackets):
    """
    Overrided.
    Fix bugs about replay, but removes everything about symbol execution.
    TODO: rewrite
    """
    def read(self, pos, size, **kwargs):
        # sanity checks
        if self.write_mode is None:
            self.write_mode = False
        elif self.write_mode is True:
            raise SimFileError("Cannot read and write to the same SimPackets")

        # sanity check on packet number and determine if data is already present
        # if pos is None:
        #     pos = len(self.content)
        if pos < 0:
            raise SimFileError("SimPacket.read(%d): Negative packet number?" % pos)
        elif pos > len(self.content):
            raise SimFileError("SimPacket.read(%d): Packet number is past frontier of %d?" % (pos, len(self.content)))
        elif pos != len(self.content):
            _, realsize = self.content[pos]
            if (realsize > size).is_true():
                # seems to be a short read
                packet = self.content[pos][0]
                if not isinstance(size, int):
                    assert(size.concrete)
                    size = size.args[0]
                result = (packet[packet.length-1:packet.length - size*8], self.state.solver.BVV(size, self.state.arch.bits))
                left = (packet[packet.length - size*8 - 1 : 0], self.state.solver.BVV(packet.length//8 - size, self.state.arch.bits))
                self.content = self.content[:pos] + [result, left] + self.content[pos+1:]
            #self.state.solver.add(realsize <= size)  # assert that the packet fits within the read request
            # if not self.state.solver.satisfiable():
            #     raise SimFileError("SimPackets could not fit the current packet into the read request of %s bytes: %s" % (size, self.content[pos]))
            #print(self.content[pos] + (pos+1,))
            return self.content[pos] + (pos+1,)
        
        


class SimPackets(angr.SimPackets):
    """
    The same with angr.SimPackets, but discard size check.
    Size check will make state unsatisfied. That's an angr bug.
    """
    def read(self, pos, size, **kwargs):
        """
        Overrided.
        Read a packet from the stream.

        :param int pos:     The packet number to read from the sequence of the stream. May be None to append to the stream.
        :param size:        The size to read. May be symbolic.
        :param short_reads: Whether to replace the size with a symbolic value constrained to less than or equal to the original size. If unspecified, will be chosen based on the state option.
        :return:            A tuple of the data read (a bitvector of the length that is the maximum length of the read) and the actual size of the read.
        """
        short_reads = kwargs.pop('short_reads', None)

        # sanity check on read/write modes
        if self.write_mode is None:
            self.write_mode = False
        elif self.write_mode is True:
            raise SimFileError("Cannot read and write to the same SimPackets")

        # sanity check on packet number and determine if data is already present
        if pos is None:
            pos = len(self.content)
        if pos < 0:
            raise SimFileError("SimPacket.read(%d): Negative packet number?" % pos)
        elif pos > len(self.content):
            raise SimFileError("SimPacket.read(%d): Packet number is past frontier of %d?" % (pos, len(self.content)))
        elif pos != len(self.content):
            _, realsize = self.content[pos]
            self.state.solver.add(realsize <= size)  # assert that the packet fits within the read request
            if not self.state.solver.satisfiable():
                raise SimFileError("SimPackets could not fit the current packet into the read request of %s bytes: %s" % (size, self.content[pos]))
            return self.content[pos] + (pos+1,)

        # typecheck
        if type(size) is int:
            size = self.state.solver.BVV(size, self.state.arch.bits)

        # The read is on the frontier. let's generate a new packet.
        orig_size = size
        max_size = None

        # if short reads are enabled, replace size with a symbol
        if short_reads is True or (short_reads is None and sim_options.SHORT_READS in self.state.options):
            size = self.state.solver.BVS('packetsize_%d_%s' % (len(self.content), self.ident), self.state.arch.bits, key=('file', self.ident, 'packetsize', len(self.content)))
            self.state.solver.add(size <= orig_size)

        # figure out the maximum size of the read
        if not self.state.solver.symbolic(size):
            max_size = self.state.solver.eval(size)
        elif self.state.solver.satisfiable(extra_constraints=(size <= self.state.libc.max_packet_size,)):
            l.info("Constraining symbolic packet size to be less than %d", self.state.libc.max_packet_size)
            if not self.state.solver.is_true(orig_size <= self.state.libc.max_packet_size):
                self.state.solver.add(size <= self.state.libc.max_packet_size)
            if not self.state.solver.symbolic(orig_size):
                max_size = min(self.state.solver.eval(orig_size), self.state.libc.max_packet_size)
            else:
                max_size = self.state.solver.max(size)
        else:
            max_size = self.state.solver.min(size)
            l.warning("Could not constrain symbolic packet size to <= %d; using minimum %d for size", self.state.libc.max_packet_size, max_size)
            self.state.solver.add(size == max_size)

        # generate the packet data and return it
        data = self.state.solver.BVS('packet_%d_%s' % (len(self.content), self.ident), max_size * self.state.arch.byte_width, key=('file', self.ident, 'packet', len(self.content)))
        packet = (data, size)
        self.content.append(packet)
        return packet + (pos+1,)