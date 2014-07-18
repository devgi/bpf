import pytest

from bpf.tcpdump_lex import get_tokens, reserved_words, constants

lex_tests = [
     ("123", "NUM"),
     ("0xff", "NUM"),
     ("0x0", "NUM"),
     ("0", "NUM"),
     ("0x123", "NUM"),
     ("icmptype", "NUM"),
     ("::", "HID6"),
     ("::1", "HID6"),
     ("fe80::219:7eff:fe46:6c42", "HID6"),
     ("::00:192.168.10.184", "HID6"),
     ("1.2.3.4", "HID"),
     ("255.255.255.255", "HID"),
     ("127.0.0.1", "HID"),
     ("12-34-56-78-9A-BC", "EID"),
     ("12:34:56:78:9A:BC", "EID"),
     ("12.34.56.78.9A.BC", "EID"),
     ("1234.5678.9ABC", "EID"),
     ("0000.0000.0000", "EID"),
 ]

lex_tests += reserved_words.items()
lex_tests += [(const, "NUM") for const in constants.keys()]


@pytest.mark.parametrize(("string", "expected_token_type"),
                         lex_tests
)
def test_tcpudmp_lex(string, expected_token_type):
    tokens = get_tokens(string)
    assert len(tokens) == 1
    tok = tokens[0]
    assert tok.type == expected_token_type


@pytest.mark.parametrize(("filter_string", "expected_number_of_tokens"),
                     [
                         ("host 10.10.15.15 or ( vlan and host 10.10.15.15 )", 9),
                         ("net 1.2.3.0/24", 4),
                         ("and src 10.5.2.3 and dst port 3389", 7),
                         ("src 10.0.2.4 and (dst port 3389 or 22)", 10),
                         ("ether[0] & 1 = 0 and ip[16] >= 224", 15),
                         ('icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply', 13),
                         ('tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet', 19),
                         ('port 80 or port 100', 5),
                         ('port 80 || port 100', 5),
                         ('host www.example.com and not (port 80 or port 25)', 11),
                         ('(tcp[0:2] > 1500 and tcp[0:2] < 1550) or (tcp[2:2] > 1500 and tcp[2:2] < 1550)', 39)
                     ])
def test_lex_complex_filters(filter_string, expected_number_of_tokens):
    tokens = get_tokens(filter_string)
    assert len(tokens) == expected_number_of_tokens