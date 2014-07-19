# SunATM header for ATM packet 
SUNATM_DIR_POS = 0
SUNATM_VPI_POS = 1
SUNATM_VCI_POS = 2
SUNATM_PKT_BEGIN_POS = 4  # Start of ATM packet

# Protocol type values in the bottom for bits of the byte at SUNATM_DIR_POS. 
PT_LANE = 0x01  # LANE
PT_LLC = 0x02  # LLC encapsulation
PT_ILMI = 0x05  # ILMI
PT_QSAAL = 0x06  # Q.SAAL