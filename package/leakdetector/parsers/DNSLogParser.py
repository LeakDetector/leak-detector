from BroLogParser import BroLogParser
from collections import defaultdict

class DNSLogParser(BroLogParser):
    
    def __init__(self, log_path):
        super(DNSLogParser, self).__init__(log_path)
        # List instead of set, so that we can count visits
        self.data = defaultdict(list)
        
    def _process_record(self, r):
        query = r['query']
        if query != '-':
            self.data['visited-subdomains'].append(query)
