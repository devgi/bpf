import pytest

from bpf.program import BPFProgram
from bpf_aot_compiler.python import compile_program

# simple packets captured in order to test the filter.
arp_packet = "ffffffffffff11223344556608060001080006040001112233445566c0a80001000000000000c0a80066000000000000000000000000000000000000"
dns_packet = "11223344556600110012345608004500003e7d61000080110000c0a8007bc0a80001d7750035002a8208ab7f0100000100000000000003646e73086d7366746e63736903636f6d0000010001"
tcp_syn_packet = "1122334455660011001234560800450000347e7d400080060000c0a8007b4a7de672300700501da41a9a0000000080022000f2390000020405b40103030201010402"

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

# tcpdump -dd "tcp
tcp_bpf_program = [
    ( 0x28, 0, 0, 0x0000000c ),
    ( 0x15, 0, 3, 0x00000800 ),
    ( 0x30, 0, 0, 0x00000017 ),
    ( 0x15, 0, 1, 0x00000006 ),
    ( 0x6, 0, 0, 0x00000044 ),
    ( 0x6, 0, 0, 0x00000000 ),
]

@pytest.mark.parametrize(("packet", "bpf_program"),
    [(tcp_syn_packet, tcp_bpf_program),
     (dns_packet, dns_bpf_program),
     (arp_packet, arp_bpf_program),
    ]
)
def test_legit_packet_pass_the_filter(packet, bpf_program):
    bpf_program = BPFProgram.from_tuple(bpf_program)
    bpf_filter = compile_program(bpf_program)
    assert bpf_filter(packet.decode('hex')) != 0


@pytest.mark.parametrize(("packet", "bpf_program"),
    [(dns_packet, tcp_bpf_program),
     (arp_packet, tcp_bpf_program),
     (tcp_syn_packet, dns_bpf_program),
     (arp_packet, dns_bpf_program),
     (tcp_syn_packet, arp_bpf_program),
     (dns_packet, arp_bpf_program),
    ]
)
def test_non_legit_packet_failed_by_the_filter(packet, bpf_program):
    bpf_program = BPFProgram.from_tuple(bpf_program)
    bpf_filter = compile_program(bpf_program)
    import IPython; IPython.embed()
    assert bpf_filter(packet.decode('hex')) == 0