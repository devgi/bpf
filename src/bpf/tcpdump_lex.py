from ply.lex import TOKEN, lex

# token with reserved words and sign alternative
t_OR = r"\|\|"
t_AND = r"&&"

# tokens without reserved words, only signs
t_GEQ = r">="
t_LEQ = r"<="
t_NEQ = r"!="
t_EQ = r"=="  # line 331
t_LSH = r"<<"
t_RSH = r">>"


# line XXX
literals = ["+", "-", "*", "/", ":", "[", "]",
            "<", ">", "(", ")", "&", "|", "="]
#
# t_S_PLUS = r"\+"
# t_S_MINUS = r"-"
# t_S_START = r"\*"
# t_S_SLASH = r"/"
# t_S_COLON = r":"
# t_S_L_SQUARE_BARCKET = r"\["
# t_S_R_SQUARE_BARCKET = r"\]"
# t_S_L_ANGLE_BARCKET = r"<"
# t_S_R_ANGLE_BARCKET = r">"
# t_S_L_BARCKET = r"\("
# t_S_R_BARCKET = r"\)"
# t_S_BITWISE_AND = r"&"
# t_S_BITWISE_OR = r"\|"
# t_S_EQUALS = r"="


# basic regex defs line 95

B_regex = r"([0-9A-Fa-f][0-9A-Fa-f]?)"


@TOKEN("$" + B_regex)
def t_AID(t):
    return t


B2_regex = r"([0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f])"

mac_regex = r"({B}:{B}:{B}:{B}:{B}:{B}|{B}\-{B}\-{B}\-{B}\-{B}\-{B}|{B}\.{B}\.{B}\.{B}\.{B}\.{B}|{B2}\.{B2}\.{B2}|{B2}{3})"
mac_regex = mac_regex.replace("{B}", B_regex)
mac_regex = mac_regex.replace("{B2}", B2_regex)


@TOKEN(mac_regex)
def t_EID(t):
    return t


# ipv6 regex.
ipv6_regex = r"""
(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|
(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|
(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|
(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|
(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|
(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|
(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|
(\A:(:[0-9a-f]{1,4}){1,7}\Z)|
(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|
(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|
(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|
(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|
(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|
(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|
(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|
(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|
(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)
"""
ipv6_regex = ''.join(ipv6_regex.split())


@TOKEN(ipv6_regex)
def t_HID6(t):
    return t


# ipv4 regex
# the original lex code in line 343 says it should look like this, but
# it cause problems, and any way how use 0xff.0xff.0xff.0xff notation to write
# IP addresses?
# ipv4_regex = r"({N}\.{N})|({N}\.{N}\.{N})|({N}\.{N}\.{N}\.{N})"
ipv4_regex = r'(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}'


# Notice that this is a function only because we want check if this is ipv4
# address before we check if its NUM token.
@TOKEN(ipv4_regex)
def t_HID(t):
    return t


constants = {
    "icmptype": 0,
    "icmpcode": 1,
    "icmp-echoreply": 0,
    "icmp-unreach": 3,
    "icmp-sourcequench": 4,
    "icmp-redirect": 5,
    "icmp-echo": 8,
    "icmp-routeradvert": 9,
    "icmp-routersolicit": 10,
    "icmp-timxceed": 11,
    "icmp-paramprob": 12,
    "icmp-tstamp": 13,
    "icmp-tstampreply": 14,
    "icmp-ireq": 15,
    "icmp-ireqreply": 16,
    "icmp-maskreq": 17,
    "icmp-maskreply": 18,
    "tcpflags": 13,
    "tcp-fin": 0x01,
    "tcp-syn": 0x02,
    "tcp-rst": 0x04,
    "tcp-push": 0x08,
    "tcp-ack": 0x10,
    "tcp-urg": 0x20,
}

N_regex = r"((0X|0x)[0-9A-Fa-f]+)|([0-9]+)"

# order the conts names from the longest to the shortest, since
# there are consts that are substrings of each other.
# exampe: "icmp-tstamp", "icmp-tstampreply"

number_regex = N_regex + "|" + \
               ('|'.join(sorted(constants.keys(), key=lambda x: -len(x))))


@TOKEN(number_regex)
def t_NUM(t):
    if t.value in constants:
        t.value = constants[t.value]
    elif t.value.lower().startswith('0x'):
        t.value = int(t.value, 16)
    else:
        t.value = int(t.value)
    return t


# line 388

reserved_words = {
    "aarp": "AARP",
    "action": "PF_ACTION",
    "addr1": "ADDR1",
    "addr2": "ADDR2",
    "addr3": "ADDR3",
    "addr4": "ADDR4",
    "address1": "ADDR1",
    "address2": "ADDR2",
    "address3": "ADDR3",
    "address4": "ADDR4",
    "ah": "AH",
    "and": "AND",
    "arp": "ARP",
    "atalk": "ATALK",
    "bcc": "BCC",
    "broadcast": "TK_BROADCAST",
    "byte": "CBYTE",
    "CARP": "CARP",
    "clnp": "CLNP",
    "connectmsg": "CONNECTMSG",
    "csnp": "CSNP",
    "decnet": "DECNET",
    "dir": "DIR",
    "direction": "DIR",
    "dpc": "DPC",
    "dst": "DST",
    "es-is": "ESIS",
    "esis": "ESIS",
    "esp": "ESP",
    "ether": "LINK",
    "fddi": "LINK",
    "fisu": "FISU",
    "gateway": "GATEWAY",
    "greater": "GREATER",
    "hdpc": "HDPC",
    "hfisu": "HFISU",
    "hlssu": "HLSSU",
    "hmsu": "HMSU",
    "hopc": "HOPC",
    "host": "HOST",
    "hsio": "HSIO",
    "hsls": "HSLS",
    "icmp": "ICMP",
    "icmp6": "ICMPV6",
    "ifname": "PF_IFNAME",
    "igmp": "IGMP",
    "igrp": "IGRP",
    "iih": "IIH",
    "ilmic": "ILMIC",
    "inbound": "INBOUND",
    "ip": "IP",
    "ip6": "IPV6",
    "ipx": "IPX",
    "is-is": "ISIS",
    "isis": "ISIS",
    "iso": "ISO",
    "l1": "L1",
    "l2": "L2",
    "lane": "LANE",
    "lat": "LAT",
    "len": "LEN",
    "less": "LESS",
    "link": "LINK",
    "llc": "LLC",
    "lsp": "LSP",
    "lssu": "LSSU",
    "lsu": "LSSU",
    "mask": "NETMASK",
    "metac": "METAC",
    "metaconnect": "METACONNECT",
    "mopdl": "MOPDL",
    "moprc": "MOPRC",
    "mpls": "MPLS",
    "msu": "MSU",
    "multicast": "TK_MULTICAST",
    "net": "NET",
    "netbeui": "NETBEUI",
    "not": "NOT",
    "oam": "OAM",
    "oamf4": "OAMF4",
    "oamf4ec": "OAMF4EC",
    "oamf4sc": "OAMF4SC",
    "on": "PF_IFNAME",
    "opc": "OPC",
    "or": "OR",
    "outbound": "OUTBOUND",
    "pim": "PIM",
    "port": "PORT",
    "portrange": "PORTRANGE",
    "ppp": "LINK",
    "pppoes": "PPPOES",
    "proto": "PROTO",
    "protochain": "PROTOCHAIN",
    "psnp": "PSNP",
    "ra": "RA",
    "RADIO": "RADIO",
    "rarp": "RARP",
    "reason": "PF_REASON",
    "rnr": "PF_RNR",
    "rset": "PF_RSET",
    "rulenum": "PF_RNR",
    "ruleset": "PF_RSET",
    "sc": "SC",
    "sca": "SCA",
    "sctp": "SCTP",
    "sio": "SIO",
    "slip": "LINK",
    "sls": "SLS",
    "snp": "SNP",
    "src": "SRC",
    "srnr": "PF_SRNR",
    "stp": "STP",
    "subrulenum": "PF_SRNR",
    "SUBTYPE": "SUBTYPE",
    "ta": "TA",
    "tcp": "TCP",
    "tr": "LINK",
    "type": "TYPE",
    "udp": "UDP",
    "vci": "VCI",
    "vlan": "VLAN",
    "vpi": "VPI",
    "VRRP": "VRRP",
    "wlan": "LINK"
}

ID_regex = r"([A-Za-z0-9]([-_.A-Za-z0-9]*[.A-Za-z0-9])?)|(\\[^ !()\n\t]+)"


@TOKEN(ID_regex)
def t_ID(t):
    t.type = reserved_words.get(t.value, "ID")
    return t


# ignore characters
t_ignore = " \r\n\t"

# define the lexer

tokens = [
             'AID',
             'EID',
             'EQ',
             'GEQ',
             'HID',
             'HID6',
             'ID',
             'LEQ',
             'LSH',
             'NEQ',
             'NUM',
             'PPPOED',
             'RSH',
             # 'S_BITWISE_AND',
             # 'S_BITWISE_OR',
             #           'S_COLON',
             #           'S_EQUALS',
             #           'S_L_ANGLE_BARCKET',
             #           'S_L_BARCKET',
             #           'S_L_SQUARE_BARCKET',
             #           'S_MINUS',
             #           'S_PLUS',
             #           'S_R_ANGLE_BARCKET',
             #           'S_R_BARCKET',
             #           'S_R_SQUARE_BARCKET',
             #           'S_SLASH',
             #           'S_START'

             # append the reserved words
         ] + list(set(reserved_words.values()))

lexer = lex()


def get_tokens(string):
    """ parse string to tokens """
    lexer.input(string)

    tokens = []
    while True:
        tok = lexer.token()
        if not tok:
            break
        else:
            tokens.append(tok)
    return tokens
