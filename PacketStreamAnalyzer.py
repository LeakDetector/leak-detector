import utils
from pcap import *
from HTTPHeaderAnalyzer import HTTPHeaderAnalyzer

class PacketStreamAnalyzer(object):

    def __init__(self):
        self.os = None
        self.languages = set()
        self.browsers = set()
        self.visited_domains = set()
        self.visited_subdomains = set()
        self.tcp_html_streams = set()
        self.google_queries = set()
        
        self.__last_query = None

    def update(self, packet):
        try:
            self.analyze_dns_message(packet.dns_header, packet.dns_data)
        except AttributeError:
            pass
        
        try:
            self.analyze_http_header(packet.http_header, packet)
        except AttributeError:
            pass

    def analyze_dns_message(self, dns_header, dns_data):
        # add all queried domains to a list
        if dns_header.message_type == 'Query':
            for query in dns_data.queries:
                self.visited_subdomains = self.visited_subdomains | {query.qname}
                if '.' in query.qname:
                    self.visited_domains = self.visited_domains | {query.qname.split('.')[-2] + '.' + query.qname.split('.')[-1]}

    def analyze_http_header(self, http_header, packet):
        h = HTTPHeaderAnalyzer(http_header, packet)
        if h.os: self.os = h.os
        self.languages = self.languages | h.languages
        self.browsers = self.browsers | h.browsers
        self.tcp_html_streams = self.tcp_html_streams | h.tcp_html_streams
                
        # with Google instant, queries are built one char at a time; don't keep the intermediaries
        if h.google_query:
            if self.__last_query and self.__last_query in h.google_query:
                self.google_queries.remove(self.__last_query)

            self.__last_query = h.google_query
            self.google_queries = self.google_queries | {h.google_query}
