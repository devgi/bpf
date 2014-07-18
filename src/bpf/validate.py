import struct

from bpf.opcodes import (BPF_CLASS, BPF_LD, BPF_LDX, BPF_MODE, BPF_MEMWORDS,
                         BPF_IMM, BPF_IND, BPF_MSH, BPF_ABS, BPF_LEN, BPF_MEM,
                         BPF_ST, BPF_STX, BPF_ALU, BPF_OP, BPF_ADD, BPF_SUB,
                         BPF_MUL, BPF_OR, BPF_AND, BPF_RSH, BPF_LSH, BPF_NEG,
                         BPF_DIV, BPF_SRC, BPF_K, BPF_JMP, BPF_JA, BPF_JEQ,
                         BPF_JGT,
                         BPF_JGE, BPF_JSET, BPF_RET, BPF_MISC
)


# /*
# * Return true if the 'fcode' is a valid filter program.
# * The constraints are that each jump be forward and to a valid
# * code, that memory accesses are within valid ranges (to the
# * extent that this can be checked statically; loads of packet
# * data have to be, and are, also checked at run time), and that
# * the code terminates with either an accept or reject.
# *
# * The kernel needs to be able to verify an application's filter code.
# * Otherwise, a bogus program could easily crash the system.
# */

BPF_MAXINSNS = 4096


def validate_opcode_field(opcode, fieldname, fieldtype):
    try:
        struct.pack(fieldtype, getattr(opcode, fieldname))
    except struct.error:
        raise ValueError("Opcode field %s contains illegal value." % fieldname)


def validate_opcode(opcode):
    # u_short	code;
    # u_char	jt;
    # u_char	jf;
    # long k
    validate_opcode_field(opcode, "code", "!H")
    validate_opcode_field(opcode, "jt", "!B")
    validate_opcode_field(opcode, "jf", "!B")
    validate_opcode_field(opcode, "k", "!L")


def bpf_validate(program):
    proglen = len(program.instructions)

    if (proglen < 1):
        raise ValueError("program is empty?")

    if (proglen > BPF_MAXINSNS):
        raise ValueError("program is too long.")

    for i, opcode in enumerate(program.instructions):
        # call validate opcode.
        validate_opcode(opcode)

        code = opcode.code

        if BPF_CLASS(code) in (BPF_LD, BPF_LDX):

            if BPF_MODE(code) in (BPF_ABS, BPF_IND, BPF_MSH, BPF_LEN, BPF_IMM):
                # nothing to do here.
                pass
            elif BPF_MODE(code) == BPF_MEM:
                if opcode.k >= BPF_MEMWORDS:
                    raise ValueError(
                        "Attempt to load value from non exists memory cell.")
            else:
                raise ValueError("Invalid mode for class LD/LDX.")

        elif (BPF_CLASS(code) in (BPF_ST, BPF_STX) and
                      opcode.k >= BPF_MEMWORDS):
            raise ValueError(
                "Attempt to store value in non exists memory cell.")

        elif BPF_CLASS(code) == BPF_ALU:
            if BPF_OP(code) in (
                    BPF_ADD, BPF_SUB, BPF_MUL, BPF_OR, BPF_AND, BPF_LSH,
                    BPF_RSH,
                    BPF_NEG):
                # nothing to do here.
                pass
            elif BPF_OP(code) == BPF_DIV and (
                            BPF_SRC(code) == BPF_K and opcode.k == 0):
                # Check for constant division by 0.
                raise ValueError("Attempt to divide by 0.")
            else:
                raise ValueError("Invalid bpf op for class ALU.")
        elif BPF_CLASS(code) == BPF_JMP:
            # Check that jumps are within the code block,
            # and that unconditional branches don't go
            # backwards as a result of an overflow.
            # Unconditional branches have a 32-bit offset,
            # so they could overflow; we check to make
            # sure they don't.  Conditional branches have
            # an 8-bit offset, and the from address is <=
            # BPF_MAXINSNS, and we assume that BPF_MAXINSNS
            # is sufficiently small that adding 255 to it
            # won't overflow.
            #
            # We know that len is <= BPF_MAXINSNS, and we
            # assume that BPF_MAXINSNS is < the maximum size
            # of a u_int, so that i + 1 doesn't overflow.
            #
            # For userland, we don't know that the from
            # or len are <= BPF_MAXINSNS, but we know that
            # from <= len, and, except on a 64-bit system,
            # it's unlikely that len, if it truly reflects
            # the size of the program we've been handed,
            # will be anywhere near the maximum size of
            # a u_int.  We also don't check for backward
            # branches, as we currently support them in
            # userland for the protochain operation.
            #
            jump_from = i + 1
            if BPF_OP(code) == BPF_JA:
                if jump_from + opcode.k >= proglen:
                    raise ValueError(
                        "Attempt to jump outside the program scope.")
            elif BPF_OP(code) in (BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET):
                if (jump_from + opcode.jt >= proglen or
                                jump_from + opcode.jf >= proglen):
                    raise ValueError(
                        "Attempt to jump outside the program scope.")
            else:
                raise ValueError("Invalid bpf op for class JMP.")

        elif BPF_CLASS(code) == BPF_RET:
            # nothing to do here
            pass
        elif BPF_CLASS(code) == BPF_MISC:
            # nothing to do here
            pass
        else:
            raise ValueError("Invalid code class.")

    # verify that the last opcode is ret.
    if BPF_CLASS(program.instructions[proglen - 1].code) != BPF_RET:
        raise ValueError("Program should end with RET.")

    return True
