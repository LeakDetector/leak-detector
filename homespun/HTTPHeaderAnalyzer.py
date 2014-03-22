import urllib

class HTTPHeaderAnalyzer:

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

    def __init__(self, header, packet):
        self.os = set()
        self.languages = set()
        self.browsers = set()
        self.tcp_html_streams = set()
        self.tcp_image_streams = set()
        self.google_queries = None

        self.__process_user_agent(header)
        self.__process_language(header)
        self.__find_interesting_streams(header, packet)
        self.__extract_google_query(header)

    def __process_user_agent(self, http_header):
        try:
            if '(' in http_header['User-Agent']:
                for token in http_header['User-Agent'].split('(')[1].split(')')[0].split(';'):
                    if 'OS X' in token:
                        self.os = self.os | { token.replace('_', '.') }
                    elif 'Windows' in token:
                        self.os = self.os | { WINDOWS[token] }

            if 'Safari' in http_header['User-Agent']:
                self.browsers = self.browsers | {'Safari'}
            elif 'Firefox' in http_header['User-Agent']:
                self.browsers = self.browsers | {'Firefox'}
            elif 'Chrome' in http_header['User-Agent']:
                self.browsers = self.browsers | {'Chrome'}
        except KeyError:
            pass

    def __process_language(self, http_header):
        try:
            self.languages = self.languages | {self.LANGUAGE[http_header['Accept-Language'][0:2]]}
        except KeyError:
            pass

    def __find_interesting_streams(self, http_header, packet):
        # Make a note if this header goes with an HTML page to speed
        # up looking for HTML pages later
        # Ditto for streams containing images
        try:
            if 'text/html' in http_header['Content-Type']:
                stream = '%s,%s,%s,%s' % (packet.source_ip, packet.source_port, packet.dest_ip, packet.dest_port)
                self.tcp_html_streams = self.tcp_html_streams | { stream }
            if 'image' in http_header['Content-Type']:
                stream = '%s,%s,%s,%s' % (packet.source_ip, packet.source_port, packet.dest_ip, packet.dest_port)
                self.tcp_image_streams = self.tcp_image_streams | { stream }
        except KeyError:
            pass

    def __extract_google_query(self, header):
        try:
            if header.method == 'GET' and header['Host'] == 'www.google.com' and '?' in header.URI:
                pairs = [(p.split('=')[0], p.split('=')[1]) for p in header.URI.split('?')[1].split('&')]
                query_attrs = dict(pairs)
                query = query_attrs['q']

                self.google_query = urllib.unquote(query).replace('+', ' ')

        except KeyError, AttributeError:
            pass
