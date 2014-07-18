import pytest

from bpf.tcpdump_yacc import parser
from bpf.program import BPFProgram

@pytest.mark.parametrize(("filter_string",),
                        [
                         ("host 10.10.15.15 or ( vlan and host 10.10.15.15 )",),
                         ("net 1.2.3.0/24",),
                         ("src 10.0.2.4",),
                         ("dst port 1.2.3.4",),
                         ("dst port 3389",),
                         ("dst port 3389 or 22",),
                         ("src 10.0.2.4 and (dst port 3389 or 22)",),
                         ("ether[0] & 1 = 0 and ip[16] >= 224",),
                         ('icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply',),
                         ('tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet',),
                         ('port 80 or port 100',),
                         ('port 80 || port 100',),
                         ('host www.example.com and not (port 80 or port 25)',),
                         ('(tcp[0:2] > 1500 and tcp[0:2] < 1550) or (tcp[2:2] > 1500 and tcp[2:2] < 1550)',),
                     ])
def test_valid_filter(filter_string):
    parser.parse(filter_string, debug=1)


@pytest.mark.parametrize(("filter_string",),
                        [
                         ("and src 10.5.2.3 and dst port 3389",),
                         ("dst port 10 + 2 * 40",),
                     ])
def test_invalid_filter(filter_string):
    with pytest.raises(RuntimeError):
        parser.parse(filter_string, debug=1)


filter_expression_to_program = {}
filter_expression_to_program['arp'] = [
    (0x28, 0, 0, 0x0000000c),
    (0x15, 0, 1, 0x00000806),
    (0x6, 0, 0, 0x00000044),
    (0x6, 0, 0, 0x00000000),
]


@pytest.mark.parametrize(("filter_string", "expected_program_c_style"),
                        filter_expression_to_program.items(),
                        ids=filter_expression_to_program.keys()
)
def test_compile_simple_programs(filter_string, expected_program_c_style):
    expected_bpf_program = BPFProgram.from_tuple(expected_program_c_style)
    bpf_program = parser.parse(filter_string, debug=1)

    assert bpf_program == expected_bpf_program

