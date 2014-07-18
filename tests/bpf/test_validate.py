import pytest

from bpf.opcodes import BPF_LD, BPF_MEM
from bpf.program import BPFProgram

# tcpdump -dd arp
arp_bpf_program = [
    (0x28, 0, 0, 0x0000000c),
    (0x15, 0, 1, 0x00000806),
    (0x6, 0, 0, 0x00000044),
    (0x6, 0, 0, 0x00000000),
]

# tcpdump -dd udp port 53
dns_bpf_program = [
    ( 0x28, 0, 0, 0x0000000c ),
    ( 0x15, 0, 10, 0x00000800 ),
    ( 0x30, 0, 0, 0x00000017 ),
    ( 0x15, 0, 8, 0x00000011 ),
    ( 0x28, 0, 0, 0x00000014 ),
    ( 0x45, 6, 0, 0x00001fff ),
    ( 0xb1, 0, 0, 0x0000000e ),
    ( 0x48, 0, 0, 0x0000000e ),
    ( 0x15, 2, 0, 0x00000035 ),
    ( 0x48, 0, 0, 0x00000010 ),
    ( 0x15, 0, 1, 0x00000035 ),
    ( 0x6, 0, 0, 0x00000044 ),
    ( 0x6, 0, 0, 0x00000000 ),
]

legit_program_load_from_memory_address = [
    (BPF_LD | BPF_MEM, 0, 0, 15),
    ( 0x6, 0, 0, 0x00000000 )
]


@pytest.mark.parametrize("bpf_program",
                         [arp_bpf_program,
                          dns_bpf_program,
                          legit_program_load_from_memory_address])
def test_legal_bpf_program_passes_validate(bpf_program):
    bpf_program = BPFProgram.from_tuple(bpf_program)
    bpf_program.validate()


bad_program_code_too_big = [
    (0xfffff, 0, 0, 0x0000000c),
]

bad_program_no_ret_at_end = [
    ( 0x28, 0, 0, 0x0000000c ),
]

bad_program_jmp_outside_the_scope = [
    ( 0x15, 0, 10, 0x00000800 ),
    ( 0x6, 0, 0, 0x00000000 )
]

bad_program_load_from_non_exists_memory_address = [
    (BPF_LD | BPF_MEM, 0, 0, 16),
    ( 0x6, 0, 0, 0x00000000 )
]

@pytest.mark.parametrize("bpf_program",
                         [bad_program_code_too_big,
                          bad_program_no_ret_at_end,
                          bad_program_load_from_non_exists_memory_address])
def test_illegal_bpf_program_fails_validate(bpf_program):
    bpf_program = BPFProgram.from_tuple(bpf_program)
    with pytest.raises(ValueError):
        bpf_program.validate()