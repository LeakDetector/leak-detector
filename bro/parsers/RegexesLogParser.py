from BroLogParser import BroLogParser

class Email(tuple):
    """
    Internal representation of an email address, which contains the address portion, 
    a parsed domain, and the plaintext.
    
    Email(plaintext) --> Email(address, domain, plaintext)"""
    
    __slots__ = ()
    _fields = ('address', 'domain', 'plaintext')
    
    def __new__(_cls, plaintext):
        domain = BroLogParser.parse_domain(plaintext)
        
        # Very basic check... the rest should be taken care of by the regexes already.
        if '@' not in plaintext:
            raise ValueError("This doesn't look like a valid email address.")
        address = plaintext.split('@')[0]
        return tuple.__new__(_cls, (address, domain, plaintext))

    def __repr__(self):
        return "Email(address=%s, domain=%s, plaintext=%s)" % self

class RegexesLogParser(BroLogParser):

    def __init__(self, log_path):
        super(RegexesLogParser, self).__init__(log_path)
    
    def _process_record(self, r):
        if r['tag'] == 'email':
            self.data[r['tag']].add(Email(r['data']))
            
        self.data[r['tag']].add(r['data'])
