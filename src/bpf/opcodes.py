#
# # The instruction encodings.
#
# # instruction classes
BPF_CLASS = lambda (code): ((code) & 0x07)
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07

## ld/ldx fields 
BPF_SIZE = lambda (code): ((code) & 0x18)
BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10
BPF_MODE = lambda (code): ((code) & 0xe0)
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xa0

## alu/jmp fields 
BPF_OP = lambda (code): ((code) & 0xf0)
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40
BPF_SRC = lambda (code): ((code) & 0x08)
BPF_K = 0x00
BPF_X = 0x08

## ret - BPF_K and BPF_X also apply 
BPF_RVAL = lambda (code): ((code) & 0x18)
BPF_A = 0x10

## misc 
BPF_MISCOP = lambda (code): ((code) & 0xf8)
BPF_TAX = 0x00
BPF_TXA = 0x80

# generic const
BPF_MEMWORDS = 16


class BPFOpcode(object):
    def __init__(self, code, jt, jf, k):
        self.code = code
        self.jt = jt
        self.jf = jf
        self.k = k

    def __repr__(self):
        return self.format_as_string()

    def format_as_tuple(self):
        return (self.code, self.jt, self.jf, self.k)

    def format_as_c(self):
        return "{ 0x%(code)x, %(jt)d, %(jf)d, 0x%(k)08x }," % self.__dict__


    def format_as_string(self, instruction_index=0):
        n = instruction_index
        v = self.k

        if self.code == BPF_RET | BPF_K:
            op = "ret"
            fmt = "#%d"

        elif self.code == BPF_RET | BPF_A:
            op = "ret"
            fmt = ""

        elif self.code == BPF_LD | BPF_W | BPF_ABS:
            op = "ld"
            fmt = "[%d]"

        elif self.code == BPF_LD | BPF_H | BPF_ABS:
            op = "ldh"
            fmt = "[%d]"

        elif self.code == BPF_LD | BPF_B | BPF_ABS:
            op = "ldb"
            fmt = "[%d]"

        elif self.code == BPF_LD | BPF_W | BPF_LEN:
            op = "ld"
            fmt = "#pktlen"

        elif self.code == BPF_LD | BPF_W | BPF_IND:
            op = "ld"
            fmt = "[x + %d]"

        elif self.code == BPF_LD | BPF_H | BPF_IND:
            op = "ldh"
            fmt = "[x + %d]"

        elif self.code == BPF_LD | BPF_B | BPF_IND:
            op = "ldb"
            fmt = "[x + %d]"

        elif self.code == BPF_LD | BPF_IMM:
            op = "ld"
            fmt = "#0x%x"

        elif self.code == BPF_LDX | BPF_IMM:
            op = "ldx"
            fmt = "#0x%x"

        elif self.code == BPF_LDX | BPF_MSH | BPF_B:
            op = "ldxb"
            fmt = "4*([%d]&0xf)"

        elif self.code == BPF_LD | BPF_MEM:
            op = "ld"
            fmt = "M[%d]"

        elif self.code == BPF_LDX | BPF_MEM:
            op = "ldx"
            fmt = "M[%d]"

        elif self.code == BPF_ST:
            op = "st"
            fmt = "M[%d]"

        elif self.code == BPF_STX:
            op = "stx"
            fmt = "M[%d]"

        elif self.code == BPF_JMP | BPF_JA:
            op = "ja"
            fmt = "%d"
            v = n + 1 + self.k

        elif self.code == BPF_JMP | BPF_JGT | BPF_K:
            op = "jgt"
            fmt = "#0x%x"

        elif self.code == BPF_JMP | BPF_JGE | BPF_K:
            op = "jge"
            fmt = "#0x%x"

        elif self.code == BPF_JMP | BPF_JEQ | BPF_K:
            op = "jeq"
            fmt = "#0x%x"

        elif self.code == BPF_JMP | BPF_JSET | BPF_K:
            op = "jset"
            fmt = "#0x%x"

        elif self.code == BPF_JMP | BPF_JGT | BPF_X:
            op = "jgt"
            fmt = "x"

        elif self.code == BPF_JMP | BPF_JGE | BPF_X:
            op = "jge"
            fmt = "x"

        elif self.code == BPF_JMP | BPF_JEQ | BPF_X:
            op = "jeq"
            fmt = "x"

        elif self.code == BPF_JMP | BPF_JSET | BPF_X:
            op = "jset"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_ADD | BPF_X:
            op = "add"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_SUB | BPF_X:
            op = "sub"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_MUL | BPF_X:
            op = "mul"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_DIV | BPF_X:
            op = "div"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_AND | BPF_X:
            op = "and"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_OR | BPF_X:
            op = "or"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_LSH | BPF_X:
            op = "lsh"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_RSH | BPF_X:
            op = "rsh"
            fmt = "x"

        elif self.code == BPF_ALU | BPF_ADD | BPF_K:
            op = "add"
            fmt = "#%d"

        elif self.code == BPF_ALU | BPF_SUB | BPF_K:
            op = "sub"
            fmt = "#%d"

        elif self.code == BPF_ALU | BPF_MUL | BPF_K:
            op = "mul"
            fmt = "#%d"

        elif self.code == BPF_ALU | BPF_DIV | BPF_K:
            op = "div"
            fmt = "#%d"

        elif self.code == BPF_ALU | BPF_AND | BPF_K:
            op = "and"
            fmt = "#0x%x"

        elif self.code == BPF_ALU | BPF_OR | BPF_K:
            op = "or"
            fmt = "#0x%x"

        elif self.code == BPF_ALU | BPF_LSH | BPF_K:
            op = "lsh"
            fmt = "#%d"

        elif self.code == BPF_ALU | BPF_RSH | BPF_K:
            op = "rsh"
            fmt = "#%d"

        elif self.code == BPF_ALU | BPF_NEG:
            op = "neg"
            fmt = ""

        elif self.code == BPF_MISC | BPF_TAX:
            op = "tax"
            fmt = ""

        elif self.code == BPF_MISC | BPF_TXA:
            op = "txa"
            fmt = ""

        else:  # default.
            op = "unimp"
            fmt = "0x%x"
            v = self.code

        # Try to format operand
        try:
            operand = fmt % v
        except TypeError:
            operand = ""

        if BPF_CLASS(self.code) == BPF_JMP and BPF_OP(self.code) != BPF_JA:
            return "(%03d) %-8s %-16s jt %d    jf %d" % (n, op, operand,
                                                       n + 1 + self.jt,
                                                       n + 1 + self.jf,
            )
        else:
            return  "(%03d) %-8s %s"  % (n, op, operand)