import gzip
import struct
import time


class CapReader(object):
    """A stateful pcap reader. Each packet is returned as a string"""

    _CAP_HEADER = "HHIIII"

    def __init__(self, filename):
        """
        Create new cap reader.

        @param filename: path to the cap file
        @type filename: str.
        """
        self.filename = filename
        try:
            self.f = gzip.open(filename, "rb")
            magic = self.f.read(4)
        except IOError:
            self.f = open(filename, "rb")
            magic = self.f.read(4)
        if magic == "\xa1\xb2\xc3\xd4":  # big endian
            self.endian = ">"
        elif  magic == "\xd4\xc3\xb2\xa1":  # little endian
            self.endian = "<"
        else:
            raise IOError("Not a pcap capture file (bad magic)")
        hdr = self.f.read(20)
        if len(hdr) < 20:
            raise IOError("Invalid pcap file (too short)")

        # parse pcap header
        (vermaj, vermin, tz, sig, snaplen, linktype) = \
                struct.unpack(self.endian + self._CAP_HEADER, hdr)

        self.linktype = linktype

    def __iter__(self):
        self.reset()
        return self

    def next(self):
        """
        implement the iterator protocol on a set of packets in a pcap file
        """
        pkt = self.read_packet()
        if pkt is None:
            raise StopIteration
        return pkt

    def read_packet(self):
        """return a single packet read from the file

        returns None when no more packets are available
        """
        hdr = self.f.read(16)
        if len(hdr) < 16:
            return None
        sec, usec, caplen, wirelen = struct.unpack(self.endian + "IIII", hdr)
        s = self.f.read(caplen)
        return s, (sec, usec, wirelen)  # caplen = len(s)

    def read_all(self, count=-1):
        """
        return a list of all packets in the pcap file with their metadata
        """
        res = []
        packet_iterator = iter(self)
        for p in packet_iterator:
            if p is None or count == 0:
                break
            count -= 1
            res.append(p)
        return res

    def read_all_packets(self, count=-1):
        """
        return a list of all packets in the pcap file without their metadata
        """
        return [packet[0] for packet in self.read_all(count)]

    def close(self):
        return self.f.close()

    def reset(self):
        """ reset cap reader and skip the header bytes """
        magic_size = 4
        header_size = struct.calcsize(self._CAP_HEADER)
        self.f.seek(magic_size + header_size, 0)

    def __repr__(self):
        return "<CapReader - %s>" % self.filename


class CapWriter(object):
    """A stream PCAP writer with more control than wrpcap()"""
    def __init__(self, filename, linktype=1, gz=False,
                 endianness="", append=False, sync=False):
        """
        linktype: the linktype of this cap file. (default 1 for Ethernet)
        gz: compress the capture on the fly.
        endianness: force an endianness (little:"<", big:">").
            Default is native.
        append: append packets to the capture file instead of truncating it.
        sync: do not bufferize writes to the capture file.
        """
        self.linktype = linktype
        self.header_present = 0
        self.append = append
        self.gz = gz
        self.endian = endianness
        self.filename = filename
        self.sync = sync
        bufsz = 4096
        if sync:
            bufsz = 0

        mode = "ab" if append else "wb"
        if gz:
            self.f = gzip.open(filename, mode, compresslevel=9)
        else:
            self.f = open(filename, mode, buffering=bufsz)

    def _write_header(self):
        self.header_present = 1

        if self.append:
            # Even if prone to race conditions, this seems to be
            # safest way to tell whether the header is already present
            # because we have to handle compressed streams that
            # are not as flexible as basic files
            g = [open, gzip.open][self.gz](self.filename, "rb")
            if g.read(16):
                return

        self.f.write(struct.pack(self.endian + "IHHIIII", 0xa1b2c3d4L,
                                 2, 4, 0, 0, 4096, self.linktype))
        self.f.flush()

    def write(self, pkt):
        """accepts a either a single packet or a list of packets
        to be written to the dumpfile
        """
        if not self.header_present:
            self._write_header()
        if type(pkt) is str:
            self._write_packet(pkt)
        else:
            for p in pkt:
                self._write_packet(p)

    def _write_packet(self, packet, sec=None, usec=None,
                      caplen=None, wirelen=None):
        """writes a single packet to the pcap file
        """
        if caplen is None:
            caplen = len(packet)
        if wirelen is None:
            wirelen = caplen
        if sec is None or usec is None:
            t = time.time()
            it = int(t)
            if sec is None:
                sec = it
            if usec is None:
                usec = int(round((t - it) * 1000000))
        self.f.write(struct.pack(self.endian + "IIII", sec,
                                 usec, caplen, wirelen))
        self.f.write(packet)
        if self.gz and self.sync:
            self.f.flush()

    def flush(self):
        return self.f.flush()

    def close(self):
        return self.f.close()

    def __repr__(self):
        return "<CapWriter - %s>" % self.filename
