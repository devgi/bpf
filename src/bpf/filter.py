import struct

from bpf.opcodes import (BPF_RET, BPF_K, BPF_LD, BPF_A, BPF_X, BPF_W,
                         BPF_ABS, BPF_H, BPF_B, BPF_LEN, BPF_LDX, BPF_IND,
                         BPF_MSH, BPF_IMM, BPF_MEM, BPF_ST, BPF_STX,
                         BPF_JMP, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JSET,
                         BPF_ALU, BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV,
                         BPF_AND, BPF_OR, BPF_LSH, BPF_RSH, BPF_NEG,
                         BPF_MISC, BPF_TAX, BPF_TXA, BPF_MEMWORDS)


SIZE_OF_INT32 = struct.calcsize("!L")  # 4
SIZE_OF_SHORT = struct.calcsize("!H")  # 2
SIZE_OF_BYTE = struct.calcsize("!B")  # 1

EXTRACT_LONG = lambda packet, k: struct.unpack("!L",
                                               packet[k: k + SIZE_OF_INT32])[0]
EXTRACT_SHORT = lambda packet, k: struct.unpack("!H",
                                                packet[k: k + SIZE_OF_SHORT])[0]
EXTRACT_BYTE = lambda packet, k: struct.unpack("!B",
                                               packet[k: k + SIZE_OF_BYTE])[0]


def bpf_filter(program, packet, wirelen=None):
    """
    Execute bpf program on a given packet.
    :param program: The bpf program to execute.
    :param packet: The captured packet to verify.
    :return: The number of bytes to read from the packet. -1 for all packet.
    """
    buflen = len(packet)
    wirelen = wirelen or buflen

    if (len(program.instructions) == 0):
        # No filter means accept all.
        return -1

    # The BPF architecture consists of the following basic elements:
    #
    # Element          Description
    #
    #   A                32 bit wide accumulator
    #   X                32 bit wide X register
    #   M[]              16 x 32 bit wide misc registers aka "scratch memory
    #                    store", addressable from 0 to 15
    A = 0
    X = 0
    mem = [0] * BPF_MEMWORDS

    pc = -1  # program counter.
    while True:
        # import pdb;pdb.set_trace()
        pc = pc + 1
        opcode = program.instructions[pc]
        k = opcode.k

        if opcode.code == BPF_RET | BPF_K:
            return k

        elif opcode.code == BPF_RET | BPF_A:
            return A

        elif opcode.code == BPF_LD | BPF_W | BPF_ABS:

            if (k + SIZE_OF_INT32 > buflen):
                return 0

            A = EXTRACT_LONG(packet, k)

        elif opcode.code == BPF_LD | BPF_H | BPF_ABS:
            if (k + SIZE_OF_SHORT > buflen):
                return 0
            A = EXTRACT_SHORT(packet, k)

        elif opcode.code == BPF_LD | BPF_B | BPF_ABS:
            if (k >= buflen):
                return 0

            A = EXTRACT_BYTE(packet, k)

        elif opcode.code == BPF_LD | BPF_W | BPF_LEN:
            A = wirelen

        elif opcode.code == BPF_LDX | BPF_W | BPF_LEN:
            X = wirelen

        elif opcode.code == BPF_LD | BPF_W | BPF_IND:
            k = X + opcode.k
            if (k + SIZE_OF_INT32 > buflen):
                return 0

            A = EXTRACT_LONG(packet, k)

        elif opcode.code == BPF_LD | BPF_H | BPF_IND:
            k = X + opcode.k
            if (k + SIZE_OF_SHORT > buflen):
                return 0

            A = EXTRACT_SHORT(packet, k)

        elif opcode.code == BPF_LD | BPF_B | BPF_IND:
            k = X + opcode.k
            if (k >= buflen):
                return 0
            A = EXTRACT_SHORT(packet, k)

        elif opcode.code == BPF_LDX | BPF_MSH | BPF_B:
            if (k >= buflen):
                return 0

            X = (EXTRACT_BYTE(packet, k) & 0xf) << 2

        elif opcode.code == BPF_LD | BPF_IMM:
            A = opcode.k

        elif opcode.code == BPF_LDX | BPF_IMM:
            X = opcode.k

        elif opcode.code == BPF_LD | BPF_MEM:
            A = mem[opcode.k]

        elif opcode.code == BPF_LDX | BPF_MEM:
            X = mem[opcode.k]

        elif opcode.code == BPF_ST:
            mem[opcode.k] = A

        elif opcode.code == BPF_STX:
            mem[opcode.k] = X

        elif opcode.code == BPF_JMP | BPF_JA:
            # No backward jumps allowed.
            pc += opcode.k

        elif opcode.code == BPF_JMP | BPF_JGT | BPF_K:
            pc += opcode.jt if (A > opcode.k) else opcode.jf

        elif opcode.code == BPF_JMP | BPF_JGE | BPF_K:
            pc += opcode.jt if (A >= opcode.k) else opcode.jf

        elif opcode.code == BPF_JMP | BPF_JEQ | BPF_K:
            pc += opcode.jt if (A == opcode.k) else opcode.jf

        elif opcode.code == BPF_JMP | BPF_JSET | BPF_K:
            pc += opcode.jt if (A & opcode.k) else  opcode.jf

        elif opcode.code == BPF_JMP | BPF_JGT | BPF_X:
            pc += opcode.jt if (A > X) else opcode.jf

        elif opcode.code == BPF_JMP | BPF_JGE | BPF_X:
            pc += opcode.jt if (A >= X) else opcode.jf

        elif opcode.code == BPF_JMP | BPF_JEQ | BPF_X:
            pc += opcode.jt if (A == X) else opcode.jf

        elif opcode.code == BPF_JMP | BPF_JSET | BPF_X:
            pc += opcode.jt if (A & X) else opcode.jf

        elif opcode.code == BPF_ALU | BPF_ADD | BPF_X:
            A += X

        elif opcode.code == BPF_ALU | BPF_SUB | BPF_X:
            A -= X

        elif opcode.code == BPF_ALU | BPF_MUL | BPF_X:
            A *= X

        elif opcode.code == BPF_ALU | BPF_DIV | BPF_X:
            if (X == 0):
                return 0
            A /= X

        elif opcode.code == BPF_ALU | BPF_AND | BPF_X:
            A &= X

        elif opcode.code == BPF_ALU | BPF_OR | BPF_X:
            A |= X

        elif opcode.code == BPF_ALU | BPF_LSH | BPF_X:
            A <<= X

        elif opcode.code == BPF_ALU | BPF_RSH | BPF_X:
            A >>= X

        elif opcode.code == BPF_ALU | BPF_ADD | BPF_K:
            A += opcode.k

        elif opcode.code == BPF_ALU | BPF_SUB | BPF_K:
            A -= opcode.k

        elif opcode.code == BPF_ALU | BPF_MUL | BPF_K:
            A *= opcode.k

        elif opcode.code == BPF_ALU | BPF_DIV | BPF_K:
            A /= opcode.k

        elif opcode.code == BPF_ALU | BPF_AND | BPF_K:
            A &= opcode.k

        elif opcode.code == BPF_ALU | BPF_OR | BPF_K:
            A |= opcode.k

        elif opcode.code == BPF_ALU | BPF_LSH | BPF_K:
            A <<= opcode.k

        elif opcode.code == BPF_ALU | BPF_RSH | BPF_K:
            A >>= opcode.k

        elif opcode.code == BPF_ALU | BPF_NEG:
            A = -A

        elif opcode.code == BPF_MISC | BPF_TAX:
            X = A

        elif opcode.code == BPF_MISC | BPF_TXA:
            A = X

        else:
            raise RuntimeError("opps?")
