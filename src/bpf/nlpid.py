# Types missing from some systems

# Network layer prototocol identifiers


ISO8473_CLNP = 0x81
ISO9542_ESIS = 0x82
ISO9542X25_ESIS = 0x8a
ISO10589_ISIS = 0x83

# this does not really belong in the nlpid.h file
# however we need it for generating nice
# IS-IS related BPF filters

ISIS_L1_LAN_IIH = 15
ISIS_L2_LAN_IIH = 16
ISIS_PTP_IIH = 17
ISIS_L1_LSP = 18
ISIS_L2_LSP = 20
ISIS_L1_CSNP = 24
ISIS_L2_CSNP = 25
ISIS_L1_PSNP = 26
ISIS_L2_PSNP = 27

ISO8878A_CONS = 0x84

ISO10747_IDRP = 0x85
