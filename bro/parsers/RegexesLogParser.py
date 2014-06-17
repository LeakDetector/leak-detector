from BroLogParser import BroLogParser

class RegexesLogParser(BroLogParser):

    def __init__(self, log_path):
        super(RegexesLogParser, self).__init__(log_path)
    
    def _process_record(self, r):
        self.data[r['tag']].add(r['data'])
