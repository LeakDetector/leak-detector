from collections import defaultdict
import tldextract

class BroLogParser(object):
    def __init__(self, log_path):
        self.log_path = log_path
        self.data = defaultdict(set)
        
        with open(self.log_path, 'r') as f:
            for line in f:
                if '#fields' in line:
                    self.fields = line.strip().split('\t')[1:]
                    break
        f.closed
        
    @classmethod
    def parse_domain(self, url):
        return tldextract.extract(url)    

    def _get_records(self):
        with open(self.log_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line != '' and line[0] != '#':
                    yield dict(zip(self.fields, line.split('\t')))
        f.closed
    records = property(_get_records)

    def analyze(self):
        for r in self.records:
            self._process_record(r)
