#import subprocess
import os
import re
from collections import defaultdict

def tcpflow_endpoint_str_to_endpoint(s):
    pieces = s.split('.')
    ip = '%d.%d.%d.%d' % (int(pieces[0]), int(pieces[1]), int(pieces[2]), int(pieces[3]))
    port = int(pieces[4])
    return (ip, port)

def endpoint_to_tcpflow_endpoint_str(e):
    octets = e[0].split('.')
    port = e[1]
    return '%s.%s.%s.%s.%05d' % (octets[0].zfill(3), octets[1].zfill(3), octets[2].zfill(3), octets[3].zfill(3), port)

def tcpflow_file_name_to_endpoints(name):
    endpoint_strs = name.split('-')
    endpoint1 = tcpflow_endpoint_str_to_endpoint(endpoint_strs[0])
    endpoint2 = tcpflow_endpoint_str_to_endpoint(endpoint_strs[1])
    return (endpoint1, endpoint2)

def endpoints_to_tcpflow_file_name(endpoint1, endpoint2):
    return '%s-%s' % (endpoint_to_tcpflow_endpoint_str(endpoint1), endpoint_to_tcpflow_endpoint_str(endpoint2))



class TCPStream(object):
    """An abstraction for a *one-directional* TCP flow (that is, each TCP
    actually has two TCP stream objects"""

    def __init__(self, flow_file):
        self.flow_file = flow_file
        self.source, self.dest = tcpflow_file_name_to_endpoints(os.path.basename(flow_file))


    def __str__(self):
        return '%s:%d -> %s:%d' % (self.source[0], self.source[1], self.dest[0], self.dest[1])

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.source == other.source and self.dest == other.dest
        else:
            return False

    def _get_ports(self):
        return (self.source[1], self.dest[1])
    ports = property(_get_ports)
    
    def _get_ip_addresses(self):
        return (self.source[0], self.dest[0])
    ip_addresses = property(_get_ip_addresses)

    def find_regexes(self, regexes):
        """Finds matches in the byte stream for various regexes.

        regexes is a dictionary mapping category names to lists of regex
        patterns of that category. (e.g., "phone numbers" might contain
        multiple regexes matching different phone number formats)"""

        with open(self.flow_file, 'r') as f:
            data = f.read()
        f.closed

        match_dict = defaultdict(list)  # category -> list of matches

        for category in regexes:
            for regex in regexes[category]:
                matches = re.findall(regex, data)
                if len(matches) > 0:
                    match_dict[category] += matches
        return match_dict
