from BroLogParser import BroLogParser
from collections import defaultdict

class FormLogParser(BroLogParser):
    def __init__(self, log_path):
        super(FormLogParser, self).__init__(log_path)
        self.data = defaultdict(list)
        
    def _process_record(self, r):
        host = r['host']
        uri = r['uri']
        data = r['formdata']
        if host != "-" and data != "-": 
            self.data['formdata'].append( (host,uri,data) )


