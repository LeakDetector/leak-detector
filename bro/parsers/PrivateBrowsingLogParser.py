from BroLogParser import BroLogParser

class PBLogParser(BroLogParser):
    
    def __init__(self, log_path):
        super(PBLogParser, self).__init__(log_path)
    
    def _process_record(self, r):
        host,uri = r['host'], r['uri']
        if uri:
            self.data['private-browsing-uris'].add(host+uri)
        else:
            self.data['private-browsing-uris'].add(host)

