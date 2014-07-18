from bpf.opcodes import BPFOpcode
from bpf.filter import bpf_filter
from bpf.validate import bpf_validate


class BPFProgram(object):
    def __init__(self, instructions=None):
        self.instructions = instructions or []

    @classmethod
    def from_tuple(cls, bpf_program):
        """
        Create bpf program from c style tuples.
        :param bpf_program: a tuple or a list contains bpf instructions
            in c style format, meaning a tuple of 4 members (code, jt, jf, k).
        :return: BPFProgram.
        """
        instructions = []
        for code, jt, jf, k in bpf_program:
            instructions.append(BPFOpcode(code, jt, jf, k))
        return BPFProgram(instructions=instructions)


    def __repr__(self):
        return self.format_as_string()

    def format_as_string(self):
        res = ""
        for idx, opcode in enumerate(self.instructions):
            res  += opcode.format_as_string(idx) + "\n"
        return res

    def format_as_c(self):
        res = ""
        for opcode in self.instructions:
            res  += opcode.format_as_c() + "\n"
        return res

    def format_as_tuple(self):
        res = []
        for opcode in self.instructions:
            res.append(opcode.format_as_tuple())
        return tuple(res)

    def apply(self, packet, wirelen=None):
        if self.validate():
            return bpf_filter(self, packet, wirelen=wirelen) != 0

    def validate(self):
        return bpf_validate(self)

    def __eq__(self, other):
        if isinstance(other, BPFProgram):
            return other.format_as_tuple() == self.format_as_tuple()
        else:
            return False

    def __hash__(self):
        return hash(self.format_as_tuple())