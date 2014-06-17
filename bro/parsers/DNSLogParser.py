from BroLogParser import BroLogParser

class DNSLogParser(BroLogParser):
    
    def __init__(self, log_path):
        super(DNSLogParser, self).__init__(log_path)
    
    def _process_record(self, r):
        query = r['query']
        if query != '-':
            self.data['visited-subdomains'].add(query)
            if '.' in query:
                self.data['visited-domains'].add(query.split('.')[-2] + '.' + query.split('.')[-1])
