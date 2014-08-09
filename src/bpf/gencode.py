import struct
import socket
from collections import namedtuple

from bpf.netconsts.ethertype import (ETHERTYPE_VEXP, ETHERTYPE_DN,
                                     ETHERTYPE_MOPDL,
                                     ETHERTYPE_PUP, ETHERTYPE_LAT,
                                     ETHERTYPE_AARP,
                                     ETHERTYPE_REVARP, ETHERTYPE_DECDNS,
                                     ETHERTYPE_VPROD,
                                     ETHERTYPE_PPPOES, ETHERTYPE_IP,
                                     ETHERTYPE_ATALK,
                                     ETHERTYPE_8021Q, ETHERTYPE_MPLS,
                                     ETHERTYPE_MOPRC,
                                     ETHERTYPE_MPLS_MULTI, ETHERTYPE_PPPOED,
                                     ETHERTYPE_8021QINQ, ETHERTYPE_IPV6,
                                     ETHERTYPE_IPX,
                                     ETHERTYPE_TRAIL, ETHERTYPE_ARP,
                                     ETHERTYPE_NS,
                                     ETHERTYPE_SPRITE, ETHERTYPE_LOOPBACK,
                                     ETHERTYPE_SCA,
                                     ETHERTYPE_DECDTS, ETHERTYPE_LANBRIDGE)

from bpf.netconsts.llc import (LLCSAP_RS511, LLCSAP_IPX, LLCSAP_NULL,
                               LLCSAP_8021D,
                               LLCSAP_SNAP, LLCSAP_PROWAY, LLCSAP_ISONS,
                               LLCSAP_GLOBAL,
                               LLCSAP_8021B_I, LLCSAP_IP, LLCSAP_PROWAYNM,
                               LLCSAP_NETBEUI,
                               LLCSAP_ISO8208, LLCSAP_8021B_G)

from bpf.netconsts.nlpid import (ISO8878A_CONS, ISO9542_ESIS, ISO10747_IDRP,
                                 ISIS_L1_PSNP,
                                 ISIS_L2_PSNP, ISIS_L1_CSNP, ISIS_L1_LSP,
                                 ISIS_L2_LAN_IIH,
                                 ISO9542X25_ESIS, ISIS_L2_LSP, ISIS_L2_CSNP,
                                 ISIS_PTP_IIH,
                                 ISIS_L1_LAN_IIH, ISO10589_ISIS, ISO8473_CLNP)

from bpf.netconsts.ppp import (PPP_MPLS_MCAST, PPP_DECNETCP, PPP_SNS,
                               PPP_STIICP,
                               PPP_MPLSCP, PPP_IPV6CP, PPP_DECNET,
                               PPP_MPLS_UCAST,
                               PPP_IPX, PPP_HELLO, PPP_ADDRESS, PPP_PAP,
                               PPP_LCP,
                               PPP_VINESCP, PPP_NSCP, PPP_NS, PPP_VINES,
                               PPP_STII,
                               PPP_IPXCP, PPP_CHAP, PPP_OSI, PPP_APPLE,
                               PPP_BRPDU,
                               PPP_IPV6, PPP_CONTROL, PPP_OSICP, PPP_LQM,
                               PPP_LUXCOM,
                               PPP_PPPD_OUT, PPP_APPLECP, PPP_IPCP, PPP_VJC,
                               PPP_VJNC,
                               PPP_IP, PPP_PPPD_IN)

from bpf.netconsts.linktype import (DLT_PPP_BSDOS, DLT_C_HDLC, DLT_PFLOG,
                                    DLT_JUNIPER_ATM2, DLT_IS_NETBSD_RAWAF,
                                    DLT_JUNIPER_MLPPP,
                                    DLT_IEEE802_15_4_NONASK_PHY,
                                    DLT_WIHART, DLT_LOOP,
                                    DLT_LINUX_PPP_WITHDIRECTION,
                                    DLT_IEEE802_16_MAC_CPS, DLT_ATM_CLIP,
                                    DLT_SYMANTEC_FIREWALL, DLT_PPP_PPPD,
                                    DLT_PFSYNC,
                                    DLT_AX25_KISS, DLT_AIRONET_HEADER,
                                    DLT_PRONET,
                                    DLT_REDBACK_SMARTEDGE, DLT_ATM_RFC1483,
                                    DLT_SLIP_BSDOS, DLT_NULL, DLT_IBM_SP,
                                    DLT_JUNIPER_ATM1, DLT_IEEE802_15_4_LINUX,
                                    DLT_NETBSD_RAWAF_AF, DLT_PPP_SERIAL,
                                    DLT_GPRS_LLC,
                                    DLT_CISCO_IOS, DLT_AURORA, DLT_GSMTAP_ABIS,
                                    DLT_JUNIPER_ISM, DLT_DBUS, DLT_IEEE802_11,
                                    DLT_GPF_F,
                                    DLT_NFLOG, DLT_IBM_SN, DLT_JUNIPER_ES,
                                    DLT_LIN,
                                    DLT_BACNET_MS_TP, DLT_SUNATM,
                                    DLT_IEEE802_11_RADIO,
                                    DLT_USB, DLT_LINUX_LAPD, DLT_X2E_SERIAL,
                                    DLT_USB_LINUX, DLT_JUNIPER_VS,
                                    DLT_JUNIPER_GGSN,
                                    DLT_AX25, DLT_JUNIPER_FIBRECHANNEL,
                                    DLT_DECT,
                                    DLT_LINUX_SLL, DLT_FDDI, DLT_RAIF1,
                                    DLT_SCTP,
                                    DLT_CAN_SOCKETCAN, DLT_EN10MB, DLT_AOS,
                                    DLT_SITA,
                                    DLT_GSMTAP_UM, DLT_BLUETOOTH_HCI_H4,
                                    DLT_JUNIPER_PIC_PEER, DLT_GPF_T,
                                    DLT_LAPB_WITH_DIR,
                                    DLT_IPNET, DLT_ERF_POS,
                                    DLT_IEEE802_15_4_NOFCS,
                                    DLT_ERF_ETH, DLT_LTALK, DLT_LINUX_EVDEV,
                                    DLT_CLASS,
                                    DLT_USER15, DLT_USER14, DLT_USER13,
                                    DLT_USER12,
                                    DLT_USER11, DLT_USER10, DLT_JUNIPER_FRELAY,
                                    DLT_FC_2,
                                    DLT_PPP, DLT_CHAOS, DLT_PPP_ETHER,
                                    DLT_JUNIPER_MFR,
                                    DLT_MPLS, DLT_PPP_WITH_DIRECTION,
                                    DLT_FLEXRAY,
                                    DLT_APPLE_IP_OVER_IEEE1394, DLT_PPI,
                                    DLT_RAW,
                                    DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
                                    DLT_JUNIPER_PPPOE,
                                    DLT_NETANALYZER, DLT_GCOM_T1E1, DLT_USBPCAP,
                                    DLT_ERF,
                                    DLT_ARCNET, DLT_SLIP,
                                    DLT_NETANALYZER_TRANSPARENT,
                                    DLT_ENC, DLT_RIO, DLT_IPOIB, DLT_IP_OVER_FC,
                                    DLT_PPP_WITH_DIR,
                                    DLT_FC_2_WITH_FRAME_DELIMS,
                                    DLT_LINUX_IRDA, DLT_JUNIPER_ETHER,
                                    DLT_ARCNET_LINUX,
                                    DLT_INFINIBAND, DLT_JUNIPER_VP, DLT_ECONET,
                                    DLT_C_HDLC_WITH_DIR, DLT_SCCP,
                                    DLT_X2E_XORAYA,
                                    DLT_JUNIPER_SRX_E2E, DLT_CAN20B,
                                    DLT_JUNIPER_ATM_CEMIC, DLT_PCI_EXP,
                                    DLT_STANAG_5066_D_PDU, DLT_GCOM_SERIAL,
                                    DLT_MTP2_WITH_PHDR, DLT_HHDLC,
                                    DLT_IEEE802_15_4,
                                    DLT_FRELAY_WITH_DIR, DLT_JUNIPER_SERVICES,
                                    DLT_MTP2,
                                    DLT_MTP3, DLT_MATCHING_MAX, DLT_IPMB_LINUX,
                                    DLT_PRISM_HEADER, DLT_CLASS_NETBSD_RAWAF,
                                    DLT_USB_LINUX_MMAPPED, DLT_TZSP,
                                    DLT_JUNIPER_PPP,
                                    DLT_MUX27010, DLT_IPV6, DLT_IPV4,
                                    DLT_JUNIPER_CHDLC,
                                    DLT_NG40, DLT_DOCSIS, DLT_USER9, DLT_USER8,
                                    DLT_USER7,
                                    DLT_USER6, DLT_USER5, DLT_USER4, DLT_USER3,
                                    DLT_USER2,
                                    DLT_USER1, DLT_USER0, DLT_LAPD,
                                    DLT_NETBSD_RAWAF,
                                    DLT_IEEE802_11_RADIO_AVS, DLT_EN3MB,
                                    DLT_MPEG_2_TS,
                                    DLT_JUNIPER_ST, DLT_IPMB, DLT_A653_ICM,
                                    DLT_JUNIPER_MONITOR, DLT_MATCHING_MIN,
                                    DLT_JUNIPER_MLFR, DLT_IPFILTER, DLT_MFR,
                                    DLT_NFC_LLCP,
                                    DLT_IEEE802_16_MAC_CPS_RADIO, DLT_CHDLC,
                                    DLT_JUNIPER_PPPOE_ATM, DLT_MOST, DLT_A429,
                                    DLT_FRELAY,
                                    DLT_DVB_CI, DLT_IEEE802)

from bpf.netconsts.sunatmpos import (PT_ILMI, PT_QSAAL, PT_LLC, PT_LANE,
                                     SUNATM_DIR_POS, SUNATM_VCI_POS,
                                     SUNATM_VPI_POS, SUNATM_PKT_BEGIN_POS)

from bpf.netconsts.archnet import (ARCTYPE_IP_OLD, ARCTYPE_INET6,
                                   ARCTYPE_ARP_OLD, ARCTYPE_BANIAN, ARCTYPE_IP,
                                   ARCTYPE_ARP, ARCTYPE_ATALK, ARCTYPE_DIAGNOSE,
                                   ARCTYPE_IPX, ARCTYPE_REVARP)

from bpf.opcodes import (BPF_SRC, BPFOpcode, BPF_DIV, BPF_RVAL, BPF_TAX,
                         BPF_LDX, BPF_MUL, BPF_IND, BPF_TXA, BPF_RET, BPF_JSET,
                         BPF_IMM, BPF_LSH, BPF_ABS, BPF_JMP, BPF_AND, BPF_OP,
                         BPF_OR, BPF_MEMWORDS, BPF_RSH, BPF_MODE, BPF_ALU,
                         BPF_MEM, BPF_JEQ, BPF_SUB, BPF_LEN, BPF_JGT, BPF_MSH,
                         BPF_ADD, BPF_MISC, BPF_MISCOP, BPF_JGE, BPF_LD, BPF_JA,
                         BPF_NEG, BPF_STX, BPF_X, BPF_CLASS, BPF_W, BPF_ST,
                         BPF_SIZE, BPF_H, BPF_K, BPF_A, BPF_B)

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


# protocols

IPPROTO_UDP = socket.IPPROTO_UDP
IPPROTO_TCP = socket.IPPROTO_TCP
IPPROTO_ICMP = socket.IPPROTO_ICMP
IPPROTO_SCTP = 132
IPPROTO_IGMP = 2
IPPROTO_IGRP = 9
IPPROTO_PIM = 103
IPPROTO_VRRP = 112
IPPROTO_CARP = 112
IPPROTO_ICMPV6 = 58
IPPROTO_AH = 51
IPPROTO_ESP = 50

PROTO_UNDEF = 0


# type to qualifier
type2qual = dict(
    LINK=Q_LINK,
    IP=Q_IP,
    ARP=Q_ARP,
    RARP=Q_RARP,
    SCTP=Q_SCTP,
    TCP=Q_TCP,
    UDP=Q_UDP,
    ICMP=Q_ICMP,
    IGMP=Q_IGMP,
    IGRP=Q_IGRP,
    PIM=Q_PIM,
    VRRP=Q_VRRP,
    CARP=Q_CARP,
    ATALK=Q_ATALK,
    AARP=Q_AARP,
    DECNET=Q_DECNET,
    LAT=Q_LAT,
    SCA=Q_SCA,
    MOPDL=Q_MOPDL,
    MOPRC=Q_MOPRC,
    IPV6=Q_IPV6,
    ICMPV6=Q_ICMPV6,
    AH=Q_AH,
    ESP=Q_ESP,
    ISO=Q_ISO,
    ESIS=Q_ESIS,
    ISIS=Q_ISIS,
    L1=Q_ISIS_L1,
    L2=Q_ISIS_L2,
    IIH=Q_ISIS_IIH,
    LSP=Q_ISIS_LSP,
    SNP=Q_ISIS_SNP,
    PSNP=Q_ISIS_PSNP,
    CSNP=Q_ISIS_CSNP,
    CLNP=Q_CLNP,
    STP=Q_STP,
    IPX=Q_IPX,
    NETBEUI=Q_NETBEUI,
    RADIO=Q_RADIO,
)

ethertype2ppptype = {
    ETHERTYPE_IP: PPP_IP,
    ETHERTYPE_IPV6: PPP_IPV6,
    ETHERTYPE_DN: PPP_DECNET,
    ETHERTYPE_ATALK: PPP_APPLE,
    ETHERTYPE_NS: PPP_NS,
    LLCSAP_ISONS: PPP_OSI,
    LLCSAP_IPX: PPP_IPX,

    # I'm assuming the "Bridging PDU"s that go
    # over PPP are Spanning Tree Protocol
    # Bridging PDUs
    LLCSAP_8021D: PPP_BRPDU,
}


# Value passed to gen_load_a() to indicate what the offset argument is relative to.
# enum e_offrel
OR_PACKET = 1  # relative to the beginning of the packet
OR_LINK = 2  # relative to the beginning of the link-layer header
OR_MACPL = 3  # relative to the end of the MAC-layer header
OR_NET = 4  # relative to the network-layer header
OR_NET_NOSNAP = 2  # relative to the network-layer header, with no SNAP header at the link layer
OR_TRAN_IPV4 = 2  # relative to the transport-layer header, with IPv4 network layer
OR_TRAN_IPV6 = 2  # relative to the transport-layer header, with IPv6 network layer

"""
Represents a single statement.
In case of conditional jump, jt and jf holds lists of the statements that
should be executed if the condition is filled.
"""
class Statement(object):
    __slots__ = ("code", "jt", "jf", "k")

    def __init__(self, code, jt=0, jf=0, k=0):
        self.code = code
        self.jt = jt
        self.jf = jf
        self.k = k

class StatementList(object):
    __slots__ = ("s", "next")

    def __init__(self, s, next=None):
        self.s = s
        self.next = next

    def sappend(self, s1):
        s0 = self
        while s0.next is not None:
            s0 = s0.next
        s0.next = s1

    def add_new_stmt(self, code, k=0):
        self.sappend(new_stmt(code, k=k))

def new_stmt(code, k=0):
    s = Statement(code, k=k)
    return StatementList(s=s)


Edge = namedtuple("Edge", ["id", "code", "succ", "pred", "next"])

class Block(object):
    __slots__ = ("id", "stmts", "s", "mark",
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
                             "val")

Arch = namedtuple("Arch", ["b", "s", "regno"])

Qual = namedtuple("Qual", ["addr", "proto", "dir", "pad"])

QErr = Qual(Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF)

class YYSType(object):
    __slots__ = (
        "blk_qual_q",
        "blk_atmfieldtype",
        "blk_mtp3fieldtype",
        "blk_block_b",
    )


JT = lambda b: b.et.succ
JF = lambda b: b.ef.succ

JMP = lambda (c): ((c)|BPF_JMP|BPF_K)

SWAPLONG = lambda (y):((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))

def _pcap_atodn(s):
    """
    Convert something to somthing
    :param s: something
    :return: (something, size)
    """
    AREASHIFT = 10
    AREAMASK = 0176000
    NODEMASK = 01777

    area, node = s.split('.')
    area = int(area)
    node = int(node)
    addr = (area << AREASHIFT ) & AREAMASK
    addr |= (node & NODEMASK)
    return addr, 32


def _pcap_atoin(s):
    """
    Convert ip string to int.
    :param s: ip string.
    :return: (addr, size)
    """
    return struct.unpack("!I", socket.inet_aton(s))[0], 32



class BPFCodegen(object):
    """
    This class encapsulate all the logic in gencode.c + gencode.h.
    All the global variable that used during the code generation process
    are declared in the __init__.
    """

    def __init__(self):
        # Hack for updating VLAN, MPLS, and PPPoE offsets.
        self.orig_linktype = self.orig_nl = self.label_stack_depth = -1

        # "off_linktype" is the offset to information in the link-layer header
        # giving the packet type.  This offset is relative to the beginning
        # of the link-layer header (i.e., it doesn't include off_ll).
        #
        # For Ethernet, it's the offset of the Ethernet type field.
        #
        # For link-layer types that always use 802.2 headers, it's the
        # offset of the LLC header.
        #
        #  For PPP, it's the offset of the PPP type field.
        #
        #  For Cisco HDLC, it's the offset of the CHDLC type field.
        #
        #  For BSD loopback, it's the offset of the AF_ value.
        #
        #  For Linux cooked sockets, it's the offset of the type field.
        #
        #  It's set to -1 for no encapsulation, in which case, IP is assumed.

        self.off_linktype = 0


        # TRUE if "pppoes" appeared in the filter; it causes link-layer type
        # checks to check the PPP header, assumed to follow a LAN-style link-
        # layer header and a PPPoE session header.
        self.is_pppoes = False

        # TRUE if "lane" appeared in the filter; it causes us to generate
        # code that assumes LANE rather than LLC-encapsulated traffic in SunATM.
        self.is_lane = False

        self.linktype = 0

        self.no_optimize = False

        # This is the offset of the beginning of the link-layer header from
        # the beginning of the raw packet data.
        #
        # It's usually 0, except for 802.11 with a fixed-length radio header.
        # (For 802.11 with a variable-length radio header, we have to generate
        # code to compute that offset; off_ll is 0 in that case.)
        self.off_ll = 0


        # If the link layer has variable_length headers, "reg_off_macpl"
        # is the register number for a register containing the length of the
        # link-layer header plus the length of any variable-length header
        # preceding the link-layer header.  Otherwise, "reg_off_macpl"
        # is -1.
        self.reg_off_macpl = 0

    def finish_parse(self, block):
        self.insert_compute_vloffsets()
        return block

    def insert_compute_vloffsets(self):
        b = Block()

        if self.linktype == DLT_PRISM_HEADER:
            s = self.gen_load_prism_llprefixlen()

        elif self.linktype == DLT_IEEE802_11_RADIO_AVS:
            s = self.gen_load_avs_llprefixlen();

        elif self.linktype == DLT_IEEE802_11_RADIO:
            s = self.gen_load_radiotap_llprefixlen();

        elif self.linktype == DLT_PPI:
            s = self.gen_load_ppi_llprefixlen();

        else:
            s = None

         # For link-layer types that have a variable-length link-layer
         # header, generate code to load the offset of the MAC-layer
         # payload into the register assigned to that offset, if any.
        if  self.linktype in (DLT_IEEE802_11, DLT_PRISM_HEADER, DLT_IEEE802_11_RADIO_AVS, DLT_IEEE802_11_RADIO, DLT_PPI):
            s = self.gen_load_802_11_header_len(s, b.stmts)

        # If we have any offset-loading code, append all the
        # existing statements in the block to those statements,
        # and make the resulting list the list of statements
        # for the block.
        if s is not None:
            b.s = s

    def gen_and(self, block1, block2):
        return block1


    def gen_or(self, block1, block2):
        return block1

    def gen_ncode(self, s, v, q):
        mask = None
        proto = q.proto
        dir = q.dir

        if s is None:
            vlen = 32
        if q.proto == Q_DECNET:
            v, vlen = _pcap_atodn(s)
        else:
            v, vlen = _pcap_atoin(s)

        if q.addr in (Q_DEFAULT, Q_HOST, Q_NET):
            if (proto == Q_DECNET):
                return self.gen_host(v, 0, proto, dir, q.addr)
            elif (proto == Q_LINK):
                self.bpf_error("illegal link layer address")
            else:
                mask = 0xffffffff
                if s == None and q.addr == Q_NET:
                    # Promote short net number
                    while v and (v & 0xff000000) == 0:
                        v <<= 8
                        mask <<= 8
                else:
                    # /* Promote short ipaddr
                    v <<= 32 - vlen
                    mask <<= 32 - vlen

                return self.gen_host(v, mask, proto, dir, q.addr)

        if q.addr == Q_PORT:
            if (proto == Q_UDP):
                proto = IPPROTO_UDP
            elif (proto == Q_TCP):
                proto = IPPROTO_TCP
            elif (proto == Q_SCTP):
                proto = IPPROTO_SCTP
            elif (proto == Q_DEFAULT):
                proto = PROTO_UNDEF
            else:
                self.bpf_error("illegal qualifier of 'port'")

            if (v > 65535):
                self.bpf_error("illegal port number %u > 65535", v);

            b = self.gen_port(v, proto, dir)
            return self.gen_or(self.gen_port6(v, proto, dir), b)

        elif q.addr == Q_PORTRANGE:
            if (proto == Q_UDP):
                proto = IPPROTO_UDP
            elif (proto == Q_TCP):
                proto = IPPROTO_TCP
            elif (proto == Q_SCTP):
                proto = IPPROTO_SCTP
            elif (proto == Q_DEFAULT):
                proto = PROTO_UNDEF
            else:
                self.bpf_error("illegal qualifier of 'portrange'")

            if (v > 65535):
                self.bpf_error("illegal port number %u > 65535", v)

            b = self.gen_portrange(v, v, proto, dir)
            return self.gen_or(self.gen_portrange6(v, v, proto, dir), b)

        elif q.addr == Q_GATEWAY:
            self.bpf_error("'gateway' requires a name");

        elif q.addr == Q_PROTO:
            return self.gen_proto(v, proto, dir)

        elif q.addr == Q_PROTOCHAIN:
            return self.gen_protochain(v, proto, dir)

        elif q.addr == Q_UNDEF:
            self.syntax()

        else:
            self.abort()


    def gen_proto_abbrev(self, proto):
        if proto == Q_SCTP:
            b1 = self.gen_proto(IPPROTO_SCTP, Q_IP, Q_DEFAULT)
            b0 = self.gen_proto(IPPROTO_SCTP, Q_IPV6, Q_DEFAULT)
            return self.gen_or(b1, b0)

        elif proto == Q_TCP:
            b1 = self.gen_proto(IPPROTO_TCP, Q_IP, Q_DEFAULT)
            b0 = self.gen_proto(IPPROTO_TCP, Q_IPV6, Q_DEFAULT)
            return self.gen_or(b1, b0)

        elif proto == Q_UDP:
            b0 = self.gen_proto(IPPROTO_UDP, Q_IP, Q_DEFAULT)
            b1 = self.gen_proto(IPPROTO_UDP, Q_IPV6, Q_DEFAULT)
            return self.gen_or(b1, b0)

        elif proto == Q_ICMP:
            return self.gen_proto(IPPROTO_ICMP, Q_IP, Q_DEFAULT);

        elif proto == Q_IGMP:
            return self.gen_proto(IPPROTO_IGMP, Q_IP, Q_DEFAULT);

        elif proto == Q_IGRP:
            return self.gen_proto(IPPROTO_IGRP, Q_IP, Q_DEFAULT);

        elif proto == Q_PIM:
            b1 = self.gen_proto(IPPROTO_PIM, Q_IP, Q_DEFAULT);
            b0 = self.gen_proto(IPPROTO_PIM, Q_IPV6, Q_DEFAULT);
            return self.gen_or(b0, b1);

        elif proto == Q_VRRP:
            return self.gen_proto(IPPROTO_VRRP, Q_IP, Q_DEFAULT);

        elif proto == Q_CARP:
            return self.gen_proto(IPPROTO_CARP, Q_IP, Q_DEFAULT);

        elif proto == Q_IP:
            return self.gen_linktype(ETHERTYPE_IP);

        elif proto == Q_ARP:
            return self.gen_linktype(ETHERTYPE_ARP);

        elif proto == Q_RARP:
            return self.gen_linktype(ETHERTYPE_REVARP);

        elif proto == Q_LINK:
            self.bpf_error("link layer applied in wrong context");

        elif proto == Q_ATALK:
            return self.gen_linktype(ETHERTYPE_ATALK);

        elif proto == Q_AARP:
            return self.gen_linktype(ETHERTYPE_AARP);

        elif proto == Q_DECNET:
            return self.gen_linktype(ETHERTYPE_DN);

        elif proto == Q_SCA:
            return self.gen_linktype(ETHERTYPE_SCA);

        elif proto == Q_LAT:
            return self.gen_linktype(ETHERTYPE_LAT);

        elif proto == Q_MOPDL:
            return self.gen_linktype(ETHERTYPE_MOPDL);

        elif proto == Q_MOPRC:
            return self.gen_linktype(ETHERTYPE_MOPRC);

        elif proto == Q_IPV6:
            return self.gen_linktype(ETHERTYPE_IPV6);

        elif proto == Q_ICMPV6:
            return self.gen_proto(IPPROTO_ICMPV6, Q_IPV6, Q_DEFAULT);

        elif proto == Q_AH:
            b1 = self.gen_proto(IPPROTO_AH, Q_IP, Q_DEFAULT);
            b0 = self.gen_proto(IPPROTO_AH, Q_IPV6, Q_DEFAULT);
            return self.gen_or(b0, b1);

        elif proto == Q_ESP:
            b1 = self.gen_proto(IPPROTO_ESP, Q_IP, Q_DEFAULT)
            b0 = self.gen_proto(IPPROTO_ESP, Q_IPV6, Q_DEFAULT)
            return self.gen_or(b0, b1)

        elif proto == Q_ISO:
            return self.gen_linktype(LLCSAP_ISONS)

        elif proto == Q_ESIS:
            return self.gen_proto(ISO9542_ESIS, Q_ISO, Q_DEFAULT)


        elif proto == Q_ISIS:
            return self.gen_proto(ISO10589_ISIS, Q_ISO, Q_DEFAULT)


        elif proto == Q_ISIS_L1:
            # all IS - IS Level1 PDU - Types
            b0 = self.gen_proto(ISIS_L1_LAN_IIH, Q_ISIS, Q_DEFAULT)
            b1 = self.gen_proto(ISIS_PTP_IIH, Q_ISIS,
                           Q_DEFAULT)  # FIXME extract the circuit-type bits
            res = self.gen_or(b0, b1)
            b0 = self.gen_proto(ISIS_L1_LSP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            b0 = self.gen_proto(ISIS_L1_CSNP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            b0 = self.gen_proto(ISIS_L1_PSNP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            return res

        elif proto == Q_ISIS_L2:
            # all IS-IS Level2 PDU-Types
            b0 = self.gen_proto(ISIS_L2_LAN_IIH, Q_ISIS, Q_DEFAULT)
            b1 = self.gen_proto(ISIS_PTP_IIH, Q_ISIS,
                           Q_DEFAULT)  # FIXME extract the circuit-type bits
            res = self.gen_or(b0, b1)
            b0 = self.gen_proto(ISIS_L2_LSP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            b0 = self.gen_proto(ISIS_L2_CSNP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            b0 = self.gen_proto(ISIS_L2_PSNP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            return res

        elif proto == Q_ISIS_IIH:
            # ll IS-IS Hello PDU-Types
            b0 = self.gen_proto(ISIS_L1_LAN_IIH, Q_ISIS, Q_DEFAULT)
            b1 = self.gen_proto(ISIS_L2_LAN_IIH, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, b1)
            b0 = self.gen_proto(ISIS_PTP_IIH, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            return res

        elif proto == Q_ISIS_LSP:
            b0 = self.gen_proto(ISIS_L1_LSP, Q_ISIS, Q_DEFAULT)
            b1 = self.gen_proto(ISIS_L2_LSP, Q_ISIS, Q_DEFAULT)
            return self.gen_or(b0, b1)

        elif proto == Q_ISIS_SNP:
            b0 = self.gen_proto(ISIS_L1_CSNP, Q_ISIS, Q_DEFAULT)
            b1 = self.gen_proto(ISIS_L2_CSNP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, b1)
            b0 = self.gen_proto(ISIS_L1_PSNP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            b0 = self.gen_proto(ISIS_L2_PSNP, Q_ISIS, Q_DEFAULT)
            res = self.gen_or(b0, res)
            return res

        elif proto == Q_ISIS_CSNP:
            b0 = self.gen_proto(ISIS_L1_CSNP, Q_ISIS, Q_DEFAULT)
            b1 = self.gen_proto(ISIS_L2_CSNP, Q_ISIS, Q_DEFAULT)
            return self.gen_or(b0, b1)


        elif proto == Q_ISIS_PSNP:
            b0 = self.gen_proto(ISIS_L1_PSNP, Q_ISIS, Q_DEFAULT)
            b1 = self.gen_proto(ISIS_L2_PSNP, Q_ISIS, Q_DEFAULT)
            return self.gen_or(b0, b1)

        elif proto == Q_CLNP:
            return self.gen_proto(ISO8473_CLNP, Q_ISO, Q_DEFAULT)

        elif proto == Q_STP:
            return self.gen_linktype(LLCSAP_8021D)

        elif proto == Q_IPX:
            return self.gen_linktype(LLCSAP_IPX)

        elif proto == Q_NETBEUI:
            return self.gen_linktype(LLCSAP_NETBEUI)

        elif proto == Q_RADIO:
            self.bpf_error("'radio' is not a valid protocol type")

        else:
            self.abort()


    # # FIXME: MY: These are global variables the affects the compiling process.(!)



    def gen_linktype(self, proto):
        linktype = self.linktype #shorcut.

        # are we checking MPLS-encapsulated packets?
        if (self.label_stack_depth > 0):
            if proto in (ETHERTYPE_IP, PPP_IP):
                # FIXME add other L3 proto IDs
                return self.gen_mpls_linktype(Q_IP);

            elif proto in (ETHERTYPE_IPV6, PPP_IPV6):
                # FIXME add other L3 proto IDs
                return self.gen_mpls_linktype(Q_IPV6)
            else:
                self.bpf_error("unsupported protocol over mpls")

        # Are we testing PPPoE packets?
        if (self.is_pppoes):
            # The PPPoE session header is part of the
            # MAC-layer payload, so all references
            # should be relative to the beginning of
            # that payload.

            # We use Ethernet protocol types inside libpcap;
            # map them to the corresponding PPP protocol types.
            proto = ethertype2ppptype[proto]
            return self.gen_cmp(OR_MACPL, self.off_linktype, BPF_H, proto)

        if linktype in (DLT_EN10MB, DLT_NETANALYZER, DLT_NETANALYZER_TRANSPARENT):
            return self.gen_ether_linktype(proto);

        elif linktype == DLT_C_HDLC:
            if proto == LLCSAP_ISONS:
                proto = (proto << 8 | LLCSAP_ISONS)

            return self.gen_cmp(OR_LINK, self.off_linktype, BPF_H, proto)

        elif linktype in (
                DLT_IEEE802_11, DLT_PRISM_HEADER, DLT_IEEE802_11_RADIO_AVS,
                DLT_IEEE802_11_RADIO, DLT_PPI):
            # Check that we have a data frame.
            b0 = self.gen_check_802_11_data_frame();

            # Now check for the specified link-layer type.
            b1 = self.gen_llc_linktype(proto);
            self.gen_and(b0, b1);
            return b1;

        elif linktype == DLT_FDDI:
            # XXX - check for asynchronous frames, as per RFC 1103.
            return self.gen_llc_linktype(proto);

        elif linktype == DLT_IEEE802:
            # XXX - check for LLC PDUs, as per IEEE 802.5.
            return self.gen_llc_linktype(proto);

        elif linktype == (DLT_ATM_RFC1483, DLT_ATM_CLIP, DLT_IP_OVER_FC):
            return self.gen_llc_linktype(proto);

        elif linktype == DLT_SUNATM:
            # If "is_lane" is set, check for a LANE-encapsulated
            # version of this protocol, otherwise check for an
            # LLC-encapsulated version of this protocol.
            #
            # We assume LANE means Ethernet, not Token Ring.
            if (self.is_lane):
                # Check that the packet doesn't begin with an
                # LE Control marker.  (We've already generated
                # a test for LANE.)
                b0 = self.gen_cmp(OR_LINK, SUNATM_PKT_BEGIN_POS, BPF_H, 0xFF00);
                self.gen_not(b0);


                # Now generate an Ethernet test.
                b1 = self.gen_ether_linktype(proto);
                self.gen_and(b0, b1);
                return b1;
            else:
                # Check for LLC encapsulation and then check the
                # protocol.
                b0 = self.gen_atmfield_code(A_PROTOTYPE, PT_LLC, BPF_JEQ, 0);
                b1 = self.gen_llc_linktype(proto);
                self.gen_and(b0, b1);
                return b1

        elif linktype == DLT_LINUX_SLL:
            return self.gen_linux_sll_linktype(proto);

        elif linktype in (DLT_SLIP, DLT_SLIP_BSDOS, DLT_RAW):
            # These types don't provide any type field; packets
            # are always IPv4 or IPv6.
            #
            # XXX - for IPv4, check for a version number of 4, and,
            # for IPv6, check for a version number of 6?
            if proto == ETHERTYPE_IP:
                # Check for a version number of 4
                return self.gen_mcmp(OR_LINK, 0, BPF_B, 0x40, 0xF0);

            elif proto == ETHERTYPE_IPV6:
                # Check for a version number of 6.
                return self.gen_mcmp(OR_LINK, 0, BPF_B, 0x60, 0xF0);

            else:
                return self.gen_false();

        elif linktype == DLT_IPV4:
            # Raw IPv4, so no type field.
            if (proto == ETHERTYPE_IP):
                return self.gen_true();  # always true

            # Checking for something other than IPv4; always false
            return self.gen_false();

        elif linktype == DLT_IPV6:
            # Raw IPv6, so no type field.
            if (proto == ETHERTYPE_IPV6):
                return self.gen_true();  # always true

            # Checking for something other than IPv6; always false
            return self.gen_false();

        elif linktype in (DLT_PPP, DLT_PPP_PPPD, DLT_PPP_SERIAL, DLT_PPP_ETHER):
            # We use Ethernet protocol types inside libpcap;
            # map them to the corresponding PPP protocol types.
            proto = ethertype2ppptype[proto]
            return self.gen_cmp(OR_LINK, self.off_linktype, BPF_H, proto)

        elif linktype == DLT_PPP_BSDOS:
            # We use Ethernet protocol types inside libpcap;
            # map them to the corresponding PPP protocol types.
            if proto == ETHERTYPE_IP:
                # Also check for Van Jacobson-compressed IP.
                # XXX - do this for other forms of PPP?
                b0 = self.gen_cmp(OR_LINK, self.off_linktype, BPF_H, PPP_IP);
                b1 = self.gen_cmp(OR_LINK, self.off_linktype, BPF_H, PPP_VJC);
                res = self.gen_or(b0, b1);
                b0 = self.gen_cmp(OR_LINK, self.off_linktype, BPF_H, PPP_VJNC);
                res = self.gen_or(res, b0);
                return res

            else:
                proto = ethertype2ppptype[proto]
                return self.gen_cmp(OR_LINK, self.off_linktype, BPF_H, proto);

        elif linktype in (DLT_NULL, DLT_LOOP, DLT_ENC):
            # For DLT_NULL, the link-layer header is a 32-bit
            # word containing an AF_ value in *host* byte order,
            # and for DLT_ENC, the link-layer header begins
            # with a 32-bit work containing an AF_ value in
            # host byte order.
            #
            # In addition, if we're reading a saved capture file,
            # the host byte order in the capture may not be the
            # same as the host byte order on this machine.
            #
            # For DLT_LOOP, the link-layer header is a 32-bit
            # word containing an AF_ value in *network* byte order.
            #
            # XXX - AF_ values may, unfortunately, be platform-
            # dependent; for example, FreeBSD's AF_INET6 is 24
            # whilst NetBSD's and OpenBSD's is 26.
            #
            # This means that, when reading a capture file, just
            # checking for our AF_INET6 value won't work if the
            # capture file came from another OS.
            if proto == ETHERTYPE_IP:
                proto = socket.AF_INET;

            elif proto == ETHERTYPE_IPV6:
                proto = socket.AF_INET6;

            else:
                # Not a type on which we support filtering.
                # XXX - support those that have AF_ values
                # #defined on this platform, at least?
                return self.gen_false()

            if (linktype == DLT_NULL or linktype == DLT_ENC):
                # The AF_ value is in host byte order, but
                # the BPF interpreter will convert it to
                # network byte order.
                #
                # If this is a save file, and it's from a
                # machine with the opposite byte order to
                # ours, we byte-swap the AF_ value.
                #
                # Then we run it through "htonl()", and
                # generate code to compare against the result.

                # NOTE: my: Here was an attempt to swap the byte order
                # of the proto - if it says so in the pcap header.
                # we don't have pcap header so we ignore it.
                proto = socket.htonl(proto);

            return self.gen_cmp(OR_LINK, 0, BPF_W, proto)

        elif linktype == DLT_PFLOG:
            # af field is host byte order in contrast to the rest of
            # the packet.
            offset_of_af_in_pfloghdr = 1
            if (proto == ETHERTYPE_IP):
                return self.gen_cmp(OR_LINK, offset_of_af_in_pfloghdr, BPF_B,
                               socket.AF_INET)
            elif (proto == ETHERTYPE_IPV6):
                return self.gen_cmp(OR_LINK, offset_of_af_in_pfloghdr, BPF_B,
                               socket.AF_INET6)
            else:
                return self.gen_false();

        elif linktype in (DLT_ARCNET, DLT_ARCNET_LINUX):
            # XXX should we check for first fragment if the protocol
            # uses PHDS?
            if proto == ETHERTYPE_IPV6:
                return self.gen_cmp(OR_LINK, self.off_linktype, BPF_B, ARCTYPE_INET6)

            elif proto == ETHERTYPE_IP:
                b0 = self.gen_cmp(OR_LINK, self.off_linktype, BPF_B, ARCTYPE_IP);
                b1 = self.gen_cmp(OR_LINK, self.off_linktype, BPF_B, ARCTYPE_IP_OLD);
                return self.gen_or(b0, b1);

            elif proto == ETHERTYPE_ARP:
                b0 = self.gen_cmp(OR_LINK, self.off_linktype, BPF_B, ARCTYPE_ARP);
                b1 = self.gen_cmp(OR_LINK, self.off_linktype, BPF_B, ARCTYPE_ARP_OLD);
                return self.gen_or(b0, b1);

            elif proto == ETHERTYPE_REVARP:
                return self.gen_cmp(OR_LINK, self.off_linktype, BPF_B, ARCTYPE_REVARP)

            elif proto == ETHERTYPE_ATALK:
                return self.gen_cmp(OR_LINK, self.off_linktype, BPF_B, ARCTYPE_ATALK)
            else:
                return self.gen_false();

        elif linktype == DLT_LTALK:
            if proto == ETHERTYPE_ATALK:
                return self.gen_true();
            else:
                return self.gen_false();

        elif linktype == DLT_FRELAY:
            # XXX - assumes a 2-byte Frame Relay header with
            # DLCI and flags.  What if the address is longer?
            if proto == ETHERTYPE_IP:
                # Check for the special NLPID for IP.
                return self.gen_cmp(OR_LINK, 2, BPF_H, (0x03 << 8) | 0xcc);

            elif ETHERTYPE_IPV6:
                # Check for the special NLPID for IPv6.
                return self.gen_cmp(OR_LINK, 2, BPF_H, (0x03 << 8) | 0x8e);

            elif LLCSAP_ISONS:
                # Check for several OSI protocols.
                #
                # Frame Relay packets typically have an OSI
                # NLPID at the beginning; we check for each
                # of them.
                #
                # What we check for is the NLPID and a frame
                # control field of UI, i.e. 0x03 followed
                # by the NLPID.
                b0 = self.gen_cmp(OR_LINK, 2, BPF_H, (0x03 << 8) | ISO8473_CLNP);
                b1 = self.gen_cmp(OR_LINK, 2, BPF_H, (0x03 << 8) | ISO9542_ESIS);
                b2 = self.gen_cmp(OR_LINK, 2, BPF_H, (0x03 << 8) | ISO10589_ISIS);
                return self.gen_or(b0, self.gen_or(b1, b2))

            else:
                return self.gen_false();

        elif linktype == DLT_MFR:
            self.bpf_error(
                "Multi-link Frame Relay link-layer type filtering not implemented");

        elif linktype in (DLT_JUNIPER_MFR, DLT_JUNIPER_MLFR, DLT_JUNIPER_MLPPP,
                          DLT_JUNIPER_ATM1,
                          DLT_JUNIPER_ATM2, DLT_JUNIPER_PPPOE,
                          DLT_JUNIPER_PPPOE_ATM,
                          DLT_JUNIPER_GGSN, DLT_JUNIPER_ES, DLT_JUNIPER_MONITOR,
                          DLT_JUNIPER_SERVICES,
                          DLT_JUNIPER_ETHER, DLT_JUNIPER_PPP, DLT_JUNIPER_FRELAY,
                          DLT_JUNIPER_CHDLC,
                          DLT_JUNIPER_VP, DLT_JUNIPER_ST, DLT_JUNIPER_ISM,
                          DLT_JUNIPER_VS,
                          DLT_JUNIPER_SRX_E2E, DLT_JUNIPER_FIBRECHANNEL,
                          DLT_JUNIPER_ATM_CEMIC):
            # just lets verify the magic number for now -
            # on ATM we may have up to 6 different encapsulations on the wire
            # and need a lot of heuristics to figure out that the payload
            # might be;
            #
            # FIXME encapsulation specific BPF_ filters
            # compare the magic number
            return self.gen_mcmp(OR_LINK, 0, BPF_W, 0x4d474300, 0xffffff00);


        elif linktype == DLT_BACNET_MS_TP:
            return self.gen_mcmp(OR_LINK, 0, BPF_W, 0x55FF0000, 0xffff0000);

        elif linktype == DLT_IPNET:
            return self.gen_ipnet_linktype(proto);

        elif linktype == DLT_LINUX_IRDA:
            self.bpf_error("IrDA link-layer type filtering not implemented");

        elif linktype == DLT_DOCSIS:
            self.bpf_error("DOCSIS link-layer type filtering not implemented");

        elif linktype in (DLT_MTP2, DLT_MTP2_WITH_PHDR):
            self.bpf_error("MTP2 link-layer type filtering not implemented");

        elif linktype == DLT_ERF:
            self.bpf_error("ERF link-layer type filtering not implemented");

        elif linktype == DLT_PFSYNC:
            self.bpf_error("PFSYNC link-layer type filtering not implemented");

        elif linktype == DLT_LINUX_LAPD:
            self.bpf_error("LAPD link-layer type filtering not implemented");

        elif linktype in (DLT_USB, DLT_USB_LINUX, DLT_USB_LINUX_MMAPPED):
            self.bpf_error("USB link-layer type filtering not implemented");

        elif linktype in (DLT_BLUETOOTH_HCI_H4, DLT_BLUETOOTH_HCI_H4_WITH_PHDR):
            self.bpf_error("Bluetooth link-layer type filtering not implemented");

        elif linktype in (DLT_CAN20B, DLT_CAN_SOCKETCAN):
            self.bpf_error("CAN link-layer type filtering not implemented");

        elif linktype in (
        DLT_IEEE802_15_4, DLT_IEEE802_15_4_LINUX, DLT_IEEE802_15_4_NONASK_PHY,
        DLT_IEEE802_15_4_NOFCS):
            self.bpf_error("IEEE 802.15.4 link-layer type filtering not implemented");

        elif linktype == DLT_IEEE802_16_MAC_CPS_RADIO:
            self.bpf_error("IEEE 802.16 link-layer type filtering not implemented");

        elif linktype == DLT_SITA:
            self.bpf_error("SITA link-layer type filtering not implemented");

        elif linktype == DLT_RAIF1:
            self.bpf_error("RAIF1 link-layer type filtering not implemented");

        elif linktype == DLT_IPMB:
            self.bpf_error("IPMB link-layer type filtering not implemented");

        elif linktype == DLT_AX25_KISS:
            self.bpf_error("AX.25 link-layer type filtering not implemented");

        # All the types that have no encapsulation should either be
        # handled as DLT_SLIP, DLT_SLIP_BSDOS, and DLT_RAW are, if
        # all packets are IP packets, or should be handled in some
        # special case, if none of them are (if some are and some
        # aren't, the lack of encapsulation is a problem, as we'd
        # have to find some other way of determining the packet type).
        #
        # Therefore, if "off_linktype" is -1, there's an error.

        if (self.off_linktype == -1):
            self.abort();

        # Any type not handled above should always have an Ethernet
        # type at an offset of "off_linktype".
        return self.gen_cmp(OR_LINK, self.off_linktype, BPF_H, proto);


    def gen_not(self,block):
        pass


    def gen_cmp(self,offrel, offset, size, v):
        pass


    def gen_mcmp(self,offrel, offset, size, v, mask):
        pass


    def gen_host(self,addr, mask, proto, dir, type):
        pass


    def gen_port(self,port, ip_proto, dir):
        pass


    def gen_port6(self,port, ip_proto, dir):
        pass


    def gen_portrange(self,port1, port2, ip_proto, dir):
        pass


    def gen_portrange6(self,port1, port2, ip_proto, dir):
        pass


    def gen_proto(self, v, proto, dir):
        pass


    def gen_protochain(self,v, proto, dir):
        pass


    def gen_mpls_linktype(self,proto):
        pass


    def gen_ether_linktype(self, proto):
        pass


    def gen_llc_linktype(self, proto):
        pass


    def gen_ipnet_linktype(self, proto):
        pass


    def gen_check_802_11_data_frame(self):
        pass


    def gen_atmfield_code(self, atmfield, jvalue, jtype, reverse):
        pass


    def gen_linux_sll_linktype(self, proto):
        pass


    def gen_false(self, ):
        return self.gen_uncond(0)


    def gen_true(self, ):
        return self.gen_uncond(1)


    def gen_uncond(self, rsense):
        pass


    def bpf_error(self, s):
        raise RuntimeError(s)


    def syntax(self):
        self.bpf_error("syntax error in filter expression")


    def abort(self):
        self.bpf_error("abort reached!")


    def gen_load_prism_llprefixlen(self):
        pass

    def gen_load_avs_llprefixlen(self):
        pass

    def gen_load_radiotap_llprefixlen(self):
        pass

    def gen_load_ppi_llprefixlen(self):
        pass

    def gen_load_802_11_header_len(self, s, snext):
        if self.reg_off_macpl == - 1:
            # No register has been assigned to the offset of
            # the MAC-layer payload, which means nobody needs
            # it; don't bother computing it - just return
            # what we already have.
            return s

        # This code is not compatible with the optimizer, as
        # we are generating jmp instructions within a normal
        # slist of instructions
        self.no_optimize = True

        # If "s" is non-null, it has code to arrange that the X register
        # contains the length of the prefix preceding the link-layer
        # header.
        #
        # Otherwise, the length of the prefix preceding the link-layer
        # header is "off_ll".
        if s is None:
            # There is no variable-length header preceding the
            # link-layer header.
            #
            # Load the length of the fixed-length prefix preceding
            # the link-layer header (if any) into the X register,
            # and store it in the reg_off_macpl register.
            # That length is off_ll.
            s = new_stmt(BPF_LDX|BPF_IMM, k= self.off_ll)

        # The X register contains the offset of the beginning of the
        # link-layer header; add 24, which is the minimum length
        # of the MAC header for a data frame, to that, and store it
        # in reg_off_macpl, and then load the Frame Control field,
        # which is at the offset in the X register, with an indexed load.

        s.add_new_stmt(BPF_MISC|BPF_TXA)
        s.add_new_stmt(BPF_ALU|BPF_ADD|BPF_K, k=24)
        s.add_new_stmt(BPF_ST, k=self.reg_off_macpl)
        s.add_new_stmt(BPF_LD|BPF_IND|BPF_B, k=0)

        # Check the Frame Control field to see if this is a data frame;
        # a data frame has the 0x08 bit (b3) in that field set and the
        # 0x04 bit (b2) clear.
        sjset_data_frame_1 = new_stmt(JMP(BPF_JSET), k=0x08)
        s.sappend(sjset_data_frame_1)

        #If b3 is set, test b2, otherwise go to the first statement of
        #the rest of the program.
        sjset_data_frame_1.s.jt = sjset_data_frame_2 = new_stmt(JMP(BPF_JSET), k=0x04)
        s.sappend(sjset_data_frame_2)
        sjset_data_frame_1.s.jf = snext

        # If b2 is not set, this is a data frame; test the QoS bit.
        # Otherwise, go to the first statement of the rest of the
        # program.
        sjset_data_frame_2.s.jt = snext;
        sjset_data_frame_2.s.jf = sjset_qos = new_stmt(JMP(BPF_JSET), k=0x80); # QoS bit
        s.sappend(sjset_qos)

        # If it's set, add 2 to reg_off_macpl, to skip the QoS
        # field.
        # Otherwise, go to the first statement of the rest of the
        # program.
        sjset_qos.s.jt = s2 = new_stmt(BPF_LD|BPF_MEM, k =self.reg_off_macpl);
        s.sappend(s2);
        s.add_new_stmt(BPF_ALU|BPF_ADD|BPF_IMM, k=2);
        s.add_new_stmt(BPF_ST, k=self.reg_off_macpl);

        # If we have a radiotap header, look at it to see whether
        # there's Atheros padding between the MAC-layer header
        # and the payload.
        #
        # Note: all of the fields in the radiotap header are
        # little-endian, so we byte-swap all of the values
        # we test against, as they will be loaded as big-endian
        # values.

        if (self.linktype == DLT_IEEE802_11_RADIO):
            # Is the IEEE80211_RADIOTAP_FLAGS bit (0x0000002) set
            # in the presence flag?
            sjset_qos.s.jf = s2 = new_stmt(BPF_LD|BPF_ABS|BPF_W, k=4);
            s.sappend(s2);

            sjset_radiotap_flags = new_stmt(JMP(BPF_JSET), k = SWAPLONG(0x00000002))
            s.sappend(sjset_radiotap_flags)


            # If not, skip all of this.
            sjset_radiotap_flags.s.jf = snext;

            # Otherwise, is the IEEE80211_RADIOTAP_TSFT bit set?
            sjset_radiotap_tsft = sjset_radiotap_flags.s.jt = new_stmt(JMP(BPF_JSET), k = SWAPLONG(0x00000001))
            s.sappend(sjset_radiotap_tsft);

            # If IEEE80211_RADIOTAP_TSFT is set, the flags field is
            # at an offset of 16 from the beginning of the raw packet
            # data (8 bytes for the radiotap header and 8 bytes for
            # the TSFT field).
            #
            # Test whether the IEEE80211_RADIOTAP_F_DATAPAD bit (0x20)
            # is set.
            sjset_radiotap_tsft.s.jt = s2 = new_stmt(BPF_LD|BPF_ABS|BPF_B, k=16);
            s.sappend(s2);

            sjset_tsft_datapad = new_stmt(JMP(BPF_JSET), k = 0x20);
            s.sappend(sjset_tsft_datapad);

            # If IEEE80211_RADIOTAP_TSFT is not set, the flags field is
            # at an offset of 8 from the beginning of the raw packet
            # data (8 bytes for the radiotap header).
            #
            # Test whether the IEEE80211_RADIOTAP_F_DATAPAD bit (0x20)
            # is set.
            sjset_radiotap_tsft.s.jf = s2 = new_stmt(BPF_LD|BPF_ABS|BPF_B, k=8);
            s.sappend(s2);

            sjset_notsft_datapad = new_stmt(JMP(BPF_JSET), k = 0x20)
            s.sappend(sjset_notsft_datapad);

            # In either case, if IEEE80211_RADIOTAP_F_DATAPAD is
            # set, round the length of the 802.11 header to
            # a multiple of 4.  Do that by adding 3 and then
            # dividing by and multiplying by 4, which we do by
            # ANDing with ~3.
            s_roundup = new_stmt(BPF_LD|BPF_MEM, k = self.reg_off_macpl);
            s.sappend(s_roundup);
            s.add_new_stmt(BPF_ALU|BPF_ADD|BPF_IMM, k = 3);
            s.add_new_stmt(BPF_ALU|BPF_AND|BPF_IMM, k=~3);
            s.add_new_stmt(BPF_ST, k = self.reg_off_macpl)

            sjset_tsft_datapad.s.jt = s_roundup;
            sjset_tsft_datapad.s.jf = snext;
            sjset_notsft_datapad.s.jt = s_roundup;
            sjset_notsft_datapad.s.jf = snext;
        else:
            sjset_qos.s.jf = snext;

        return s;