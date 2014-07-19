PPP_ADDRESS = 0xff  # The address byte value
PPP_CONTROL = 0x03  # The control byte value

PPP_PPPD_IN = 0x00  # non-standard for DLT_PPP_PPPD
PPP_PPPD_OUT = 0x01  # non-standard for DLT_PPP_PPPD

# Protocol numbers
PPP_IP = 0x0021  # Raw IP
PPP_OSI = 0x0023  # OSI Network Layer
PPP_NS = 0x0025  # Xerox NS IDP
PPP_DECNET = 0x0027  # DECnet Phase IV
PPP_APPLE = 0x0029  # Appletalk
PPP_IPX = 0x002b  # Novell IPX
PPP_VJC = 0x002d  # Van Jacobson Compressed TCP/IP
PPP_VJNC = 0x002f  # Van Jacobson Uncompressed TCP/IP
PPP_BRPDU = 0x0031  # Bridging PDU
PPP_STII = 0x0033  # Stream Protocol (ST-II)
PPP_VINES = 0x0035  # Banyan Vines
PPP_IPV6 = 0x0057  # Internet Protocol version 6

PPP_HELLO = 0x0201  # 802.1d Hello Packets
PPP_LUXCOM = 0x0231  # Luxcom
PPP_SNS = 0x0233  # Sigma Network Systems
PPP_MPLS_UCAST = 0x0281  # rfc 3032
PPP_MPLS_MCAST = 0x0283  # rfc 3022

PPP_IPCP = 0x8021  # IP Control Protocol
PPP_OSICP = 0x8023  # OSI Network Layer Control Protocol
PPP_NSCP = 0x8025  # Xerox NS IDP Control Protocol
PPP_DECNETCP = 0x8027  # DECnet Control Protocol
PPP_APPLECP = 0x8029  # Appletalk Control Protocol
PPP_IPXCP = 0x802b  # Novell IPX Control Protocol
PPP_STIICP = 0x8033  # Strean Protocol Control Protocol
PPP_VINESCP = 0x8035  # Banyan Vines Control Protocol
PPP_IPV6CP = 0x8057  # IPv6 Control Protocol
PPP_MPLSCP = 0x8281  # rfc 3022

PPP_LCP = 0xc021  # Link Control Protocol
PPP_PAP = 0xc023  # Password Authentication Protocol
PPP_LQM = 0xc025  # Link Quality Monitoring
PPP_CHAP = 0xc223  # Challenge Handshake Authentication Protocol