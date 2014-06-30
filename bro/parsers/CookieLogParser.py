from BroLogParser import BroLogParser
from collections import defaultdict

class CookieLogParser(BroLogParser):
    def __init__(self, log_path):
        super(CookieLogParser, self).__init__(log_path)
        
    def _process_record(self, r):
        host = r['host']
        cookie = r['cookie']
        if host != "-":
            self.data['cookies'].append( (host,cookie) )


