from BroLogParser import BroLogParser
from collections import defaultdict

class PBLogParser(BroLogParser):
    
    def __init__(self, log_path):
        super(PBLogParser, self).__init__(log_path)
        # List instead of set, so that we can count visits
        self.data = defaultdict(list)
    
    def _process_record(self, r):
        host,uri = r['host'], r['uri']
        if uri:
            self.data['private-browsing-uris'].append(host+uri)
        else:
            self.data['private-browsing-uris'].append(host)

