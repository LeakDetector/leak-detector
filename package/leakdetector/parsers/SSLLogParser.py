from BroLogParser import BroLogParser
from collections import defaultdict

class SSLLogParser(BroLogParser):
    def __init__(self, log_path):
        super(SSLLogParser, self).__init__(log_path)
        # List instead of set, so that we can count visits
        self.data = defaultdict(list)
        
    def _process_record(self, r):
        host = r['server_name']
        if host != "-": 
            self.data['https-servers'].append(host)


