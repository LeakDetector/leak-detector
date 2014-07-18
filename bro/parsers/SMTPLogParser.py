from BroLogParser import BroLogParser
from collections import defaultdict

class SMTPLogParser(BroLogParser):
    def __init__(self, log_path):
        super(SMTPLogParser, self).__init__(log_path)
        self.data = defaultdict(list)
        
    def _process_record(self, r):
        from_addr = r['from']
        to_addr = r['to']
        subject = r['subject']
        if from_addr != '-' or to_addr != '-' or subject != '-':
            self.data['email-activity'].append( (from_addr, to_addr, subject) )
        else:
            self.data['email-activity-generic'].append(r['helo'])


