from collections import namedtuple

# # Address qualifiers.

Q_HOST = 1
Q_NET = 2
Q_PORT = 3
Q_GATEWAY = 4
Q_PROTO = 5
Q_PROTOCHAIN = 6
Q_PORTRANGE = 7

# # Protocol qualifiers. 

Q_LINK = 1
Q_IP = 2
Q_ARP = 3
Q_RARP = 4
Q_SCTP = 5
Q_TCP = 6
Q_UDP = 7
Q_ICMP = 8
Q_IGMP = 9
Q_IGRP = 10

Q_ATALK = 11
Q_DECNET = 12
Q_LAT = 13
Q_SCA = 14
Q_MOPRC = 15
Q_MOPDL = 16

Q_IPV6 = 17
Q_ICMPV6 = 18
Q_AH = 19
Q_ESP = 20

Q_PIM = 21
Q_VRRP = 22

Q_AARP = 23

Q_ISO = 24
Q_ESIS = 25
Q_ISIS = 26
Q_CLNP = 27

Q_STP = 28

Q_IPX = 29

Q_NETBEUI = 30

# # IS-IS Levels 
Q_ISIS_L1 = 31
Q_ISIS_L2 = 32
# # PDU types 
Q_ISIS_IIH = 33
Q_ISIS_LAN_IIH = 34
Q_ISIS_PTP_IIH = 35
Q_ISIS_SNP = 36
Q_ISIS_CSNP = 37
Q_ISIS_PSNP = 38
Q_ISIS_LSP = 39

Q_RADIO = 40

Q_CARP = 41

# Directional qualifiers.

Q_SRC = 1
Q_DST = 2
Q_OR = 3
Q_AND = 4
Q_ADDR1 = 5
Q_ADDR2 = 6
Q_ADDR3 = 7
Q_ADDR4 = 8
Q_RA = 9
Q_TA = 10

Q_DEFAULT = 0
Q_UNDEF = 255

# ATM types 
A_METAC = 22  # Meta signalling Circuit
A_BCC = 23  # Broadcast Circuit
A_OAMF4SC = 24  # Segment OAM F4 Circuit
A_OAMF4EC = 25  # End-to-End OAM F4 Circuit
A_SC = 26  # Signalling Circuit
A_ILMIC = 27  # ILMI Circuit
A_OAM = 28  # OAM cells : F4 only
A_OAMF4 = 29  # OAM F4 cells: Segment + End-to-end
A_LANE = 30  # LANE traffic
A_LLC = 31  # LLC-encapsulated traffic

# # Based on Q.2931 signalling protocol 
A_SETUP = 41  # Setup message
A_CALLPROCEED = 42  # Call proceeding message
A_CONNECT = 43  # Connect message
A_CONNECTACK = 44  # Connect Ack message
A_RELEASE = 45  # Release message
A_RELEASE_DONE = 46  # Release message

# ATM field types 
A_VPI = 51
A_VCI = 52
A_PROTOTYPE = 53
A_MSGTYPE = 54
A_CALLREFTYPE = 55


# returns Q.2931 signalling messages for
# establishing and destroying switched
# virtual connection
A_CONNECTMSG = 70


# returns Q.2931 signalling messages for
# establishing and destroying predefined
# virtual circuits, such as broadcast
# circuit, oamf=4 segment circuit, oamf=4
# end-to-end circuits, ILMI circuits or
# connection signalling circuit.
A_METACONNECT = 71


# MTP2 types
M_FISU = 22  # FISU
M_LSSU = 23  # LSSU
M_MSU = 24  # MSU

# MTP2 HSL types
MH_FISU = 25  # FISU for HSL
MH_LSSU = 26  # LSSU
MH_MSU = 27  # MSU

# MTP3 field types 
M_SIO = 1
M_OPC = 2
M_DPC = 3
M_SLS = 4

# MTP3 field types in case of MTP2 HSL 
MH_SIO = 5
MH_OPC = 6
MH_DPC = 7
MH_SLS = 8



"""
Represents a single statement.
In case of conditional jump, jt and jf holds lists of the statements that
should be executed if the condition is filled.
"""
Statement = namedtuple("Statements", ["code", "jt", "jf", "k"])


Edge = namedtuple("Edge", ["id", "code", "succ", "pred", "next"])

Block = namedtuple("Block", ["id", "stmts", "s", "mark",
                             "longjt",
                             "longjf",
                             "level",
                             "offset",
                             "sense",
                             "et",
                             "ef",
                             "head",
                             "link",
                             "dom",
                             "closure",
                             "in_edges",
                             "val"])

Arch = namedtuple("Arch", ["b", "s", "regno"])

Qual = namedtuple("Qual", ["addr", "proto", "dir", "pad"])

JT = lambda b: b.et.succ
JF = lambda b: b.ef.succ


def finish_parse(block):
    return block