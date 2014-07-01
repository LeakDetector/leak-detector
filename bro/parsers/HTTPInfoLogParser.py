from BroLogParser import BroLogParser

class FormLogParser(BroLogParser):
    def __init__(self, log_path):
        super(FormLogParser, self).__init__(log_path)
        
    def _process_record(self, r):
        host = r['host']
        uri = r['uri']
        if host != "-" or uri != "-": 
            self.data['http-pages'].add( (host,uri) )


