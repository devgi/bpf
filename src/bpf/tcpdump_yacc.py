import ply.yacc as yacc
from tcpdump_lex import tokens
from gencode import (finish_parse, gen_and, gen_or, gen_not, type2qual,
                     gen_proto_abbrev, YYSType, QErr)


def QSET(q, p, d, a):
    q.proto = p
    q.dir = d
    q.addr = a


def p_prog(p):
    """prog : expr"""
    p[0] = finish_parse(p[1].blk_block_b)


# line 324
def p_expression(p):
    """expr : expr AND term
            | expr AND id
            | expr OR term
            | expr OR id
            | term"""
    if len(p) == 2:  # term
        p[0] = p[1]
    elif p[2] == "and":
        p[0] = gen_and(p[1], p[3])
    elif p[2] == "or":
        p[0] = gen_or(p[1], p[3])


# line 334
def p_id(p):
    """id : nid
          | pnum
          | paren pid ')'"""


# line 339
def p_nid(p):
    """nid : ID
           | HID '/' NUM
           | HID NETMASK HID
           | HID
           | HID6 '/' NUM
           | HID6
           | EID
           | AID
           | not ID"""


def p_not(p):
    """not : NOT
           | '!'"""


def p_paren(p):
    """paren : '('"""


def p_eq(p):
    """eq : EQ
          | '='"""


# line 399
def p_pid(p):
    """pid : nid
           | qid AND id
           | qid OR id"""


# line 403
def p_qid(p):
    """qid : pnum
           | pid"""


def p_term(p):
    """term : rterm
            | not term"""
    if p.slice[1].type == "rterm":
        p[0] = p[1]
    else:
        p[2].b = gen_not(p[2].blk_block_b)
        p[0] = p[2]


def p_head(p):
    """head : pqual dqual aqual
            | pqual dqual
            | pqual aqual
            | pqual PROTO
            | pqual PROTOCHAIN
            | pqual ndaqual"""


# line 417
def p_rterm(p):
    """rterm : head id
             | paren expr ')'
             | pname
             | arth relop arth
             | arth irelop arth
             | other
             | atmtype
             | atmmultitype
             | atmfield atmvalue
             | mtp2type
             | mtp3field mtp3value"""
    if p.slice[1].type == 'pname':
        p[0] = YYSType()
        p[0].blk_block_b = gen_proto_abbrev(p[1])
        p[0].blk_qual_q = QErr;


# line 432
def p_pqual(p):
    """pqual : pname
             |"""


# line 435
def p_dqual(p):
    """dqual : SRC
             | DST
             | SRC OR DST
             | DST OR SRC
             | SRC AND DST
             | DST AND SRC
             | ADDR1
             | ADDR2
             | ADDR3
             | ADDR4
             | RA
             | TA"""


# line 450
def p_aqual(p):
    """aqual : HOST
             | NET
             | PORT
             | PORTRANGE"""


# line 456
def p_ndaqual(p):
    """ndaqual : GATEWAY"""


# line 458
def p_pname(p):
    """pname : LINK
             | IP
             | ARP
             | RARP
             | SCTP
             | TCP
             | UDP
             | ICMP
             | IGMP
             | IGRP
             | PIM
             | VRRP
             | CARP
             | ATALK
             | AARP
             | DECNET
             | LAT
             | SCA
             | MOPDL
             | MOPRC
             | IPV6
             | ICMPV6
             | AH
             | ESP
             | ISO
             | ESIS
             | ISIS
             | L1
             | L2
             | IIH
             | LSP
             | SNP
             | PSNP
             | CSNP
             | CLNP
             | STP
             | IPX
             | NETBEUI
             | RADIO"""
    p[0] = type2qual[p.slice[1].type]


def p_other(p):
    """other : pqual TK_BROADCAST
            | pqual TK_MULTICAST
            | LESS NUM
            | GREATER NUM
            | CBYTE NUM byteop NUM
            | INBOUND
            | OUTBOUND
            | VLAN pnum
            | VLAN
            | MPLS pnum
            | MPLS
            | PPPOED
            | PPPOES
            | pfvar
            | pqual p80211"""


def p_pfvar(p):
    """pfvar : PF_IFNAME ID
            | PF_RSET ID
            | PF_RNR NUM
            | PF_SRNR NUM
            | PF_REASON reason
            | PF_ACTION action    """


def p_p80211(p):
    """p80211 :   TYPE type SUBTYPE subtype
              | TYPE type
              | SUBTYPE type_subtype
              | DIR dir"""


def p_type(p):
    """type : NUM
            | ID"""


def p_subtype(p):
    """subtype : NUM
               | ID"""


def p_type_subtype(p):
    """type_subtype : ID"""


def p_dir(p):
    """dir : NUM
           | ID"""


# line 596
def p_reason(p):
    """reason : NUM
              | ID"""


def p_action(p):
    """action : ID """


def p_relop(p):
    """relop : '>'
             | GEQ
             | eq"""


def p_irelop(p):
    """irelop : '<'
              | LEQ
              | NEQ"""


def p_arth(p):
    """arth : pnum
            | narth"""


# line 614
def p_narth(p):
    """narth : pname '[' arth ']'
            | pname '[' arth ':' NUM ']'
            | arth '+' arth
            | arth '-' arth
            | arth '*' arth
            | arth '/' arth
            | arth '&' arth
            | arth '|' arth
            | arth LSH arth
            | arth RSH arth
            | paren narth ')'
            | LEN"""
    # should be there. cause problems so comment out.
    # | S_MINUS arth %prec S_MINUS


# line 628
def p_byteop(p):
    """byteop : '&'
              | '|'
              | '>'
              | eq"""


def p_pnum(p):
    """pnum : NUM
            | paren NUM ')'"""


def p_atmtype(p):
    """atmtype : LANE
            | LLC
            | METAC
            | BCC
            | OAMF4EC
            | OAMF4SC
            | SC
            | ILMIC"""


def p_atmmultitype(p):
    """atmmultitype : OAM
                    | OAMF4
                    | CONNECTMSG
                    | METACONNECT"""


def p_atmfield(p):
    """atmfield : VPI
                | VCI"""


def p_atmvalue(p):
    """atmvalue :  atmfieldvalue
                | relop NUM
                | irelop NUM
                | paren atmlistvalue ')' """


def p_atmfieldvalue(p):
    """atmfieldvalue : NUM"""


def p_atmlistvalue(p):
    """atmlistvalue : atmfieldvalue
                    | atmlistvalue OR atmfieldvalue"""


def p_mtp2type(p):
    """mtp2type : FISU
                | LSSU
                | MSU
                | HFISU
                | HLSSU
                | HMSU"""


def p_mtp3field(p):
    """mtp3field : SIO
                | OPC
                | DPC
                | SLS
                | HSIO
                | HOPC
                | HDPC
                | HSLS"""


def p_mtp3value(p):
    """mtp3value :  mtp3fieldvalue
                | relop NUM
                | irelop NUM
                | paren mtp3listvalue ')'"""


def p_mtp3fieldvalue(p):
    """mtp3fieldvalue : NUM"""


def p_mtp3listvalue(p):
    """mtp3listvalue : mtp3fieldvalue
                     | mtp3listvalue OR mtp3fieldvalue"""


def p_error(p):
    print "Syntax error in input!"
    raise RuntimeError(p)


parser = yacc.yacc()


def compile_filter(expression):
    return parser.parse(expression, )
