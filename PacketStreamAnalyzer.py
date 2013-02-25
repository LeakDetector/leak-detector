from pcap import *

VERBOSE = False

class PacketStreamAnalyzer(object):
    
    WINDOWS = {
        'Windows NT 6.2': 'Windows 8',
        'Windows NT 6.1': 'Windows 7',
        'Windows NT 6.0': 'Windows Vista',
        'Windows NT 5.2': 'Windows Server 2003 or Windows XP x64 Edition',
        'Windows NT 5.1': 'Windows XP',
        'Windows NT 5.01': 'Windows 2000, Service Pack 1 (SP1)',
        'Windows NT 5.0': 'Windows 2000',
        'Windows NT 4.0': 'Microsoft Windows NT 4.0',
        'Windows 98': 'Windows 98',
        'Windows 95': 'Windows 95',
        'Windows CE': 'Windows CE'
    }

    LANGUAGE = {
        'en': 'English',
        'es': 'Spanish',
        'fr': 'French',
        'ja': 'Japanese',
        'nl': 'Dutch',
        'de': 'German',
        'zh': 'Chinese',
        'ko': 'Korean',
        'pt': 'Portuguese',
        'it': 'Italian'
    }

    def __init__(self, verbose=False):
        VERBOSE = verbose
        self.os = ''
        self.languages = set()
        self.browsers = set()
        self.visited_domains = set()
        self.visited_subdomains = set()
        self.tcp_html_streams = set()

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

        # Get user-agent
        try:
            if '(' in http_header['User-Agent']:
                for token in http_header['User-Agent'].split('(')[1].split(')')[0].split(';'):
                    if 'OS X' in token:
                        self.os = token.replace('_', '.')
                    elif 'Windows' in token:
                        self.os = WINDOWS[token]

            if 'Safari' in http_header['User-Agent']:
                self.browsers = self.browsers | {'Safari'}
            elif 'Firefox' in http_header['User-Agent']:
                self.browsers = self.browsers | {'Firefox'}
            elif 'Chrome' in http_header['User-Agent']:
                self.browsers = self.browsers | {'Chrome'}
        except KeyError:
            pass

        # Get language
        try:
            self.languages = self.languages | {self.LANGUAGE[http_header['Accept-Language'][0:2]]}
        except KeyError:
            pass

        # Make a note if this header goes with an HTML page to speed
        # up looking for HTML pages later
        try:
            if 'text/html' in http_header['Content-Type']:
                stream = '%s,%s,%s,%s' % (packet.source_ip, packet.source_port, packet.dest_ip, packet.dest_port)
                self.tcp_html_streams = self.tcp_html_streams | { stream }
        except KeyError:
            pass
