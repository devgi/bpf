from bpf.program import BPFProgram


simple_program_as_tuple = (
    (0x28, 0, 0, 0x0000000c),
    (0x15, 0, 9, 0x00000800),
    (0x30, 0, 0, 0x00000017),
    (0x15, 2, 0, 0x00000084),
    (0x15, 1, 0, 0x00000006),
    (0x15, 0, 5, 0x00000011),
    (0x28, 0, 0, 0x00000014),
    (0x45, 3, 0, 0x00001fff),
    (0xb1, 0, 0, 0x0000000e),
    (0x48, 0, 0, 0x00000010),
    (0x15, 2, 0, 0x0000007b),
    (0x28, 0, 0, 0x00000001),
    (0x15, 0, 1, 0x00000002),
    (0x6, 0, 0, 0x00000044),
    (0x6, 0, 0, 0x00000000),
)

simple_program_c_style = """
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 9, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 5, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 3, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 2, 0, 0x0000007b },
{ 0x28, 0, 0, 0x00000001 },
{ 0x15, 0, 1, 0x00000002 },
{ 0x6, 0, 0, 0x00000044 },
{ 0x6, 0, 0, 0x00000000 },

"""

simple_program_as_string = """
(000) ldh      [12]
(001) jeq      #0x800           jt 2    jf 11
(002) ldb      [23]
(003) jeq      #0x84            jt 6    jf 4
(004) jeq      #0x6             jt 6    jf 5
(005) jeq      #0x11            jt 6    jf 11
(006) ldh      [20]
(007) jset     #0x1fff          jt 11    jf 8
(008) ldxb     4*([14]&0xf)
(009) ldh      [x + 16]
(010) jeq      #0x7b            jt 13    jf 11
(011) ldh      [1]
(012) jeq      #0x2             jt 13    jf 14
(013) ret      #68
(014) ret      #0

"""

def fix_string(string):
    """ remove first line (asserts it empty)"""
    lines = string.splitlines()
    assert not lines[0]
    return "\n".join(lines[1:])

def test_bpf_program_format_as_c():
    program = BPFProgram.from_tuple(simple_program_as_tuple)
    assert program.format_as_c() == fix_string(simple_program_c_style)

def test_bpf_program_format_as_string():
    program = BPFProgram.from_tuple(simple_program_as_tuple)
    assert program.format_as_string() == fix_string(simple_program_as_string)

def test_bpf_program_format_as_tuple():
    program = BPFProgram.from_tuple(simple_program_as_tuple)
    assert program.format_as_tuple() == simple_program_as_tuple

def test_bpf_program_equals():
    program1 = BPFProgram.from_tuple(simple_program_as_tuple)
    program2 = BPFProgram.from_tuple(program1.format_as_tuple())
    assert program1 == program2

def test_bpf_program_hash():
    program1 = BPFProgram.from_tuple(simple_program_as_tuple)
    program2 = BPFProgram.from_tuple(program1.format_as_tuple())
    assert hash(program1) == hash(program2)