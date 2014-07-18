import pytest

from bpf.opcodes import BPFOpcode


example_opcodes = [

    (BPFOpcode(0x6, 0, 0, 0),  # opcode value
     0,
     r"(000) ret      #0",  # as string
     r"{ 0x6, 0, 0, 0x00000000 },",),  # as c code.

    (BPFOpcode(0x15, 0, 1, 0x2),
     12,
     r"(012) jeq      #0x2             jt 13    jf 14",
     r"{ 0x15, 0, 1, 0x00000002 },"),

    (BPFOpcode(0xb1, 0, 0, 0xe),
     8,
     r"(008) ldxb     4*([14]&0xf)",
     r"{ 0xb1, 0, 0, 0x0000000e },"),
]


@pytest.mark.parametrize(("opcode", "expected_format_c"),
                         [(opcode, c_format) for (opcode, _, _, c_format) in
                          example_opcodes]
)
def test_bpf_format_as_c(opcode, expected_format_c):
    assert opcode.format_as_c() == expected_format_c


@pytest.mark.parametrize(("opcode", "index", "expected_string_format"),
                         [(opcode, index, string_format) for
                          (opcode, index, string_format, _) in example_opcodes]
)
def test_bpf_format_as_string(opcode, index, expected_string_format):
    assert opcode.format_as_string(
        instruction_index=index) == expected_string_format
