import os
import sys
import datetime
import struct
from ctypes import *
import winpcapy
import binascii


class PCapException(Exception):
    "Generic PCapException. All other exceptions in the library sub-class this."
    pass
    

class PCapPermissionDeniedException(PCapException):
    "exception to represent when permission is denied to a network adapter"
    pass
    

class PCapInvalidNetworkAdapter(PCapException):
    "exception to represent when an invalid network adapter is specified"
    pass
    

class PCapCorruptPacket(PCapException):
    "exception that represents when a corrupt (invalid) packet is found"
    pass
    

class PCap(object):
    def __init__(self):
        # create a mutable character buffer (ctype array of c_char) for later 
        # error parsing errors will be stored in this buffer and then passed 
        # when constructing the exception object by the PCapWrapper object.
        self._error_buffer = create_string_buffer(winpcapy.PCAP_ERRBUF_SIZE)
        
    def raise_exception(self, source):
        "reads internal error buffer and raises appropriate python exception"
        # ugly to grep on errbuff to raise exception, but no other viable 
        # solution this will at least let higher level programming to be 
        # able to expect exceptions
        if source == 'errorbuffer':
            msg = self._error_buffer.value
            
        if msg.endswith("Permission denied"):
            raise PCapPermissionDeniedException(msg)
        else:
            raise PCapException(msg)
        
    def get_interfaces_iter(self):
        "generator over string representations of available sniffable network devices."
        try:
            # create a pointer to a pcap_if struct. the pcap_if struct is 
            # pretty much a linked list node with information that will be
            # filled in by pcap_findalldevs_ex
            devices = POINTER(winpcapy.pcap_if_t)()
            # populate pcap_if struct linked list with a list of devices...
            if winpcapy.pcap_findalldevs(devices, self._error_buffer) == -1:
                self.raise_exception(source='errorbuffer')
            # yield node names of linked list in form of a generator
            d = devices.contents
            while True:
                yield d.name
                if d.next: 
                    d = d.next.contents
                else:
                    break
        except:
            self.raise_exception(source='errorbuffer')
        finally:
            # always release the list of interfaces back to the system
            winpcapy.pcap_freealldevs(devices)
            
    def get_interfaces(self):
        "returns list of the available local network devices to sniff based on results of get_interfaces_iter"
        return list(self.get_interfaces_iter())
    

class PacketPortion(object):
    """Represents a portion of a network packet such as the Ethernet Header or IP Header. This class is not used directly
    but is instead inherited by other headers and such."""
    def __init__(self, packet_portion):
        self.elems = self.struct_.unpack(packet_portion)

class EthernetHeader(PacketPortion):
    """Native Python object to represent the Ethernet Header of a network packet."""
    # locations in header of the target and sender mac addresses such that
    # they can easily be humanly accessible from _get_mac_str method.
    TARGET = 0
    SENDER = 1
    
    struct_ = struct.Struct('>6s6sH')
    
    def _get_mac_str(self, elem):
        "returns string representation of MAC address"
        assert elem in (0,1)
        # convert binary representations into their hexadecimal version 
        # since that's howa MAC address is conventionally represented. 
        # then convert to proper looking MAC with ':'s.
        mac_hex_str = binascii.b2a_hex(self.elems[elem])
        return ':'.join((l+w for (l,w) in\
            zip(mac_hex_str[0::2], mac_hex_str[1::2])))
        
    __get_target_address = lambda self: self._get_mac_str(self.TARGET)
    __get_sender_address = lambda self: self._get_mac_str(self.SENDER)
    target_mac_address = property(__get_target_address, 
        doc="string representation of target MAC address")
    sender_mac_address = property(__get_sender_address, 
        doc="string representation of destination MAC address")
        
class IPHeader(PacketPortion):
    SOURCE = 8
    DEST = 9
    
    # human readable versions of different values within the IP header.. 
    #NOTE: these dicts do NOT contain all the possible values that could be 
    # found. however, the values present should suffice for the nature of this project...
    VERSION = {
        4:'IPv4',
        5:'ST',
        6:'IPv6/SIP',
        7:'TP/IX',
        8:'PIP',
        9:'TUBA'
    }
    
    PROTOCOL = {
        1:'ICMP',
        6:'TCP',
        17:'UDP'
    }

    # based on RFC -- version referenced available at http://www.networksorcery.com/enp/protocol/ip.htm.
    struct_ = struct.Struct('>BBHHHBBH4s4s')

    def _get_version_str(self):
        v = self.elems[0] >> 4
        return self.VERSION.get(v,v)
    version = property(_get_version_str)

    def _get_protocol_str(self):
        v = self.elems[6]
        return self.PROTOCOL.get(v,v)
    protocol = property(_get_protocol_str)

    def _get_address_str(self, elem):
        "returns string representation of IP address. elem must be in (cls.SOURCE, cls.DEST)"
        assert elem in (8,9) # see constants defined under IPHeader
        ip_hex_str = binascii.b2a_hex(self.elems[elem])
        return '.'.join((str(int(l+w, 16)) for (l,w) in\
            zip(ip_hex_str[0::2], ip_hex_str[1::2])))
        
    __get_destination_address = lambda self: self._get_address_str(self.DEST)
    __get_source_address = lambda self: self._get_address_str(self.SOURCE)
    destination_ip_address = property(__get_destination_address, 
        doc="string form of destination IP address")
    source_ip_address = property(__get_source_address, 
        doc="string form of source IP address")
    
class TCPHeader(PacketPortion):
    SOURCE = 0
    DEST = 1

    # based on RFC -- version referenced available at http://www.networksorcery.com/enp/protocol/tcp.htm.
    struct_ = struct.Struct('>HHLLBBHHH')

    def _get_port_str(self, elem):
        return str(self.elems[elem])

    __get_source_port = lambda self: self._get_port_str(self.SOURCE)
    __get_destination_port = lambda self: self._get_port_str(self.DEST)
    source_port = property(__get_source_port, 
        doc="string form of source port number")
    destination_port = property(__get_destination_port, 
        doc="string form of destination port number")

    def _get_sequence_num_str(self):
        return str(self.elems[2])
    sequence_number = property(_get_sequence_num_str)

    def _get_ack_num_str(self):
        return str(self.elems[3])
    acknowledgment_number = property(_get_ack_num_str)

    def _get_hdr_len(self):
        return int(self.elems[4] >> 4) * 4
    length = property(_get_hdr_len)
    
class UDPHeader(PacketPortion):
    SOURCE = 0
    DEST = 1

    # based on RFC -- version referenced available at http://www.networksorcery.com/enp/protocol/ip.htm.
    struct_ = struct.Struct('>HHHH') 

    def _get_port_str(self, elem):
        return str(self.elems[elem])

    __get_source_port = lambda self: self._get_port_str(self.SOURCE)
    __get_destination_port = lambda self: self._get_port_str(self.DEST)
    source_port = property(__get_source_port, 
        doc="string form of source port number")
    destination_port = property(__get_destination_port, 
        doc="string form of destination port number")

    def _get_hdr_len(self):
        return 8
    length = property(_get_hdr_len)
        
class DNSQuery():
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype_ = qtype
        self.qclass_ = qclass

    TYPE = {
        01:'A',
        02:'NS',
        05:'CNAME',
        06:'SOA',
        15:'MX',
        16:'TXT'
    }

    CLASS = {
        01:'IN'
    }

    def _get_type_str(self):
        return self.TYPE.get(self.qtype_, self.qtype_)
    qtype = property(_get_type_str)
    
    def _get_class_str(self):
        return self.CLASS.get(self.qclass_, self.qclass_)
    qclass = property(_get_class_str)

class DNSResourceRecord(PacketPortion):
    pass  # TODO: finish

class DNSData(PacketPortion):
    # based on RFC -- version referenced available at http://www.networksorcery.com/enp/protocol/dns.htm.
    def __init__(self, packet_portion, header):
        # treat data portion as array of unsigned chars
        fmt = '>%iB' % len(packet_portion)  
        self.struct_ = struct.Struct(fmt)
        super( DNSData, self ).__init__(packet_portion)

        # make a list of queries
        self.queries = []
        pos = 0
        for i in range(header.num_questions):
            qname = ''
            while int(self.elems[pos]) != 0:
                if qname != '':
                    qname += '.'
                num_chars = int(self.elems[pos])
                pos += 1
                qname += binascii.b2a_hex(packet_portion[pos:pos+num_chars]).decode("hex")
                pos += num_chars
            # get type and class
            pos += 1  #advance past the null octet marking end of name
            qtype = int(struct.Struct('>H').unpack(packet_portion[pos:pos+2])[0])
            qclass = int(struct.Struct('>H').unpack(packet_portion[pos+2:pos+4])[0])
            self.queries.append(DNSQuery(qname, qtype, qclass))

class DNSHeader(PacketPortion):
    # based on RFC -- version referenced available at http://www.networksorcery.com/enp/protocol/dns.htm.
    struct_ = struct.Struct('>HHHHHH') 

    def _get_message_type(self):
        return 'Query' if self.elems[1] >> 15 == 0 else 'Response'
    message_type = property(_get_message_type)

    def _get_num_questions(self):
        return int(self.elems[2])
    num_questions = property(_get_num_questions)

    def _get_num_answer_rrs(self):
        return int(self.elems[3])
    num_answer_rrs = property(_get_num_answer_rrs)
    
    def _get_num_authority_rrs(self):
        return int(self.elems[5])
    num_authority_rrs = property(_get_num_authority_rrs)
    
    def _get_num_additional_rrs(self):
        return int(self.elems[4])
    num_additional_rrs = property(_get_num_additional_rrs)

class HTTPHeader(dict):
    def __init__(self, packet_portion):
        super( HTTPHeader, self).__init__()
        self.method = ''
        self.URI = ''
        self.status = ''
        for line in packet_portion.split('\r\n'):
            if ':' in line:
                key,val = line.split(':', 1)
                self[key.strip()] = val.strip()
            elif 'GET' in line:
                self.method = 'GET'
                self.URI = line.split(' ')[1]
            elif '200 OK' in line:
                self.status = '200 OK'

class NetworkPacket(object):
    # ENUM of port => application mappings. munged from:
    # http://www.iana.org/assignments/port-numbers.
    APPLICATION = {
        20:'FTP Data',
        21:'FTP Control',
        22:'SSH',
        23:'Telnet',
        25:'SMTP',
        53:'DNS',
        80:'HTTP',
        110:'POP3',
        115:'SFTP',
        123:'NTP',
        143:'IMAP',
        443:'HTTPS',
        546:'DHCP',
        547:'DHCP',
        554:'RTSP',
        3389:'RDP',
        873:'rsync',
        989:'FTPS Data',
        990:'FTPS Control'
    }
    
    def __init__(self, header, packet):
        self.timestamp = \
            datetime.datetime.fromtimestamp(header.contents.ts.tv_sec)
        self.length = header.contents.len
        self.bytes = [packet[x] for x in range(0, header.contents.len)]
        self.data = ''.join(struct.pack('B', b) for b in self.bytes)
        
        self.ethernet_header = EthernetHeader(self.data[0:14])
        self.ip_header = IPHeader(self.data[14:34])
        if self.ip_header.protocol == 'TCP':
            # if ethernet_header + ip_header + tcp_header length is smaller than
            # 55 than some piece of data is missing and we have a corrupt tcp message
            if self.length < 55:
                raise PCapCorruptPacket
            else:
                self.transport_header = TCPHeader(self.data[34:54])
                self.payload = self.data[54:self.length]  #TODO: right upper bound?
        elif self.ip_header.protocol == 'UDP':
            self.transport_header = UDPHeader(self.data[34:42])
            self.payload = self.data[42:self.length]  #TODO: right upper bound?
        else:
            self.payload = self.data[34:self.length]
            
        # set some attributes at the NetworkPacket level so that
        # self.__dict__ can be used within __str__. might as well make
        # available to outside if we are defining dict anyways even though
        # all the information is available within the header objects contained
        # within the NetworkPacket object...
        self.sender_mac = self.ethernet_header.sender_mac_address
        self.target_mac = self.ethernet_header.target_mac_address
        self.ip_version = self.ip_header.version
        self.ip_protocol = self.ip_header.protocol
        self.source_ip = self.ip_header.source_ip_address
        self.dest_ip = self.ip_header.destination_ip_address
        if hasattr (self, 'transport_header'):
            self.source_port = self.transport_header.source_port
            self.dest_port = self.transport_header.destination_port
            self.application = self._get_app_str()
            self.trans_hdr_len = self.transport_header.length

            # look for DNS packets
            if self.application == 'DNS':
                self.dns_header = DNSHeader(self.data[42:54])
                self.dns_data = DNSData(self.data[54:self.length], self.dns_header)

            # look for HTTP packets
            if self.application == 'HTTP' and self.length > 34 + self.transport_header.length: # check length because it could just be a TCP handshake
                self.http_header = HTTPHeader(self.data[34+self.transport_header.length:self.length])

        else:
            self.source_port = self.dest_port = self.application = 'unknown'

    def _get_app_str(self):
        if hasattr(self, 'transport_header'):
            return self.APPLICATION.get(int(self.transport_header.source_port))\
                or self.APPLICATION.get(int(self.transport_header.destination_port))\
                or 'Unknown'

    def __str__(self):
        str_ = """%(timestamp)s
           ETHERNET \t Sender MAC: %(sender_mac)s\t\tTarget MAC: %(target_mac)s
                 IP \t Source IP: %(source_ip)s\t\tDestination IP: %(dest_ip)s\t\tVersion: %(ip_version)s\t\tProtocol: %(ip_protocol)s\t\t
          TRANSPORT \t Source Port: %(source_port)s\t\t\tDestination Port: %(dest_port)s \t\tLength: %(trans_hdr_len)s\t\tApplication: %(application)s""" % self.__dict__
        if self.ip_header.protocol == 'TCP':
            str_ = '\n'.join((str_, "\t   TCP INFO \t Sequence Number: %s\t\tAcknowledgement Number %s"\
                % (self.transport_header.sequence_number, self.transport_header.acknowledgment_number)))
        return str_


class NetworkCapture(PCap):
    def __init__(self):
        PCap.__init__(self)

    #TODO: WRITE THIS!
    def set_filter(self, filter_, optimize=True):
        pass
        # subnet mask is integer form of 255.255.255.254
        # create pointer for bpf_program struct
        #bpf_prog = POINTER(winpcapy.bpf_program)()
        #optimize = 1 if optimize else 0
        #try:
        #winpcapy.pcap_compile(
        #    self._pcap_t, 
        #    bpf_prog, 
        #    filter_, 
        #    optimize, 
        #    netmask)
        #except:
        #    pass
            #print self._pcapw.pcap_geterr(self._pcap_t)
        #if winpcapy.pcap_compile(self._pcap_t, bpf_prog, filter_, optimize, netmask) == -1:
        #    raise PCapException(self._pcapw.pcap_geterr(self._pcap_t))
        #if self._pcapw.pcap_setfilter(self._pcap_t, bpf_prog) == -1:
        #    raise PCapException(self._pcapw.pcap_geterr())
        #self._pcapw.pcap_freecode(bpf_prog)
        
    def get_packets(self, filter):
        header = POINTER(winpcapy.pcap_pkthdr)()
        packet = POINTER(c_ubyte)()
        rtr = 1
        try:
            while rtr >= 0:
                rtr = winpcapy.pcap_next_ex(self._pcap_t, header, packet)
                if self.__class__ == LiveNetworkCapture and self.dumper_t:
                    winpcapy.pcap_dump(self.dumper_t, header, packet)
                    #winpcapy.pcap_dump_flush(self.dumper_t)
                if rtr > 0:
                    try:
                        network_packet = NetworkPacket(header=header, packet=packet)
                        if filter(network_packet):
                            yield network_packet
                    except PCapCorruptPacket:
                        continue
                    
        except (KeyboardInterrupt, SystemExit), e:
             sys.exit()

class LiveNetworkCapture(NetworkCapture):
    dumper_t = None
    
    def __init__(self, network_adapter, packet_size=65536, promiscious=True, wait_period=10):
        NetworkCapture.__init__(self)
        if network_adapter not in self.get_interfaces():
            raise PCapInvalidNetworkAdapter("The network adapter specified '%s' does\
not exist or access is denied." % network_adapter)
        # pcap_open_live wants an int not a bool so must cast.
        promisc = 1 if promiscious else 0
        self._pcap_t = winpcapy.pcap_open_live(network_adapter, packet_size,
            promisc, wait_period, self._error_buffer)
        
    def dump_to_file(self, file_path):
        self.dumper_t = winpcapy.pcap_dump_open(self._pcap_t, file_path)
        
    def close(self):
        if self.dumper_t:
            winpcapy.pcap_dump_flush(self.dumper_t)
            winpcapy.pcap_dump_close(self.dumper_t)
        winpcapy.pcap_close(self._pcap_t)
        
class OfflineNetworkCapture(NetworkCapture):
    def __init__(self, file_path):
        NetworkCapture.__init__(self)
        try:
            self._pcap_t = winpcapy.pcap_open_offline(file_path, self._error_buffer)
        except:
            self.raise_exception(source='errorbuffer')
            
    def close(self):
        winpcapy.pcap_close(self._pcap_t)


if __name__ == '__main__':
    # basic troubleshooting if called directly.
    #q = LiveNetworkCapture('en1')
    #q.dump_to_file('test2.pcap')
    #iter = q.get_packets()
    #for i in range(0,100):
    #    print iter.next()
    #for l in q.get_packets():
    #    print i, l,'\n'
    #    i += 1
    #q.close()
    f = OfflineNetworkCapture("test2.pcap")
    for p in f.get_packets():
        print p
    f.close()
