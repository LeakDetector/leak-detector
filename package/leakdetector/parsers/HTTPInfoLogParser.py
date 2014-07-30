from BroLogParser import BroLogParser

class HTTPInfoLogParser(BroLogParser):
    def __init__(self, log_path):
        super(HTTPInfoLogParser, self).__init__(log_path)
        
    def _process_record(self, r):
        host = r['host']
        uri = r['uri']
        if host != "-" or uri != "-": 
            self.data['http-queries'].add( (host,uri) )


