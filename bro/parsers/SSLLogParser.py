from BroLogParser import BroLogParser

class SSLLogParser(BroLogParser):
    
    def __init__(self, log_path):
        super(SSLLogParser, self).__init__(log_path)
    
    def _process_record(self, r):
        host = r['server_name']
        if host != "-": 
            self.data['https-servers'].add(host)

