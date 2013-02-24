from pcap import *

class UserStats(object):

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

    def __init__(self):
        self.os = ''
        self.languages = set()
        self.browsers = set()
        self.visited_domains = set()
        self.visited_subdomains = set()
        self.page_titles = set()
    
    def update(self, packet):
        try:
            self.analyze_dns_message(packet.dns_header, packet.dns_data)
        except AttributeError:
            pass
        
        try:
            self.analyze_http_header(packet.http_header)
        except AttributeError:
            pass

    def update_from_html(self, html):
        if '<title>' in html:
            title = html.split('<title>')[1].split('</title>')[0]
            print title
            self.page_titles = self.page_titles | {title}
        

    def analyze_dns_message(self, dns_header, dns_data):
        # add all queried domains to a list
        if dns_header.message_type == 'Query':
            for query in dns_data.queries:
                self.visited_subdomains = self.visited_subdomains | {query.qname}
                if '.' in query.qname:
                    self.visited_domains = self.visited_domains | {query.qname.split('.')[-2] + '.' + query.qname.split('.')[-1]}

    def analyze_http_header(self, http_header):

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

        try:
            self.languages = self.languages | {self.LANGUAGE[http_header['Accept-Language'][0:2]]}
        except KeyError:
            pass

    def __str__(self):
        str_ = """The following data is available to anyone on your network:
GENERAL
  OS: %(os)s
  Language: %(languages)s
  Browsers: %(browsers)s

VISITED DOMAINS\n %(visited_domains)s

VISITED PAGES\n %(page_titles)s""" % self.__dict__
        return str_
