import subprocess
import os
import re

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
    def __init__(self, flow_file, data_dir):
        self.__data_dir = data_dir

        self.endpoints = tcpflow_file_name_to_endpoints(flow_file)


    def __str__(self):
        return '%s:%d <-> %s:%d' % (self.endpoints[0][0], self.endpoints[0][1], self.endpoints[1][0], self.endpoints[1][1])

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.endpoints[1] == other.endpoints[1] and self.endpoints[0] == other.endpoints[0]) or (self.endpoints[1] == other.endpoints[0] and self.endpoints[0] == other.endpoints[1])
        else:
            return False

    def _get_ports(self):
        return (self.endpoints[0][1], self.endpoints[1][1])
    ports = property(_get_ports)
    
    def _get_ip_addresses(self):
        return (self.endpoints[0][0], self.endpoints[1][0])
    ip_addresses = property(_get_ip_addresses)

    def __get_http_data(self, e1, e2):
        fname = '%s-HTTPBODY' % endpoints_to_tcpflow_file_name(e1, e2)
        fpath = os.path.join(self.__data_dir, fname)
        if os.path.exists(fpath):
            with open(fpath, 'r') as f:
                data = f.read()
            f.closed
        else:
            data = None
        return data

    def _get_http_data(self):
        return (self.__get_http_data(self.endpoints[0], self.endpoints[1]), self.__get_http_data(self.endpoints[1], self.endpoints[0]))
    http_data = property(_get_http_data)
