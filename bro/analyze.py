from collections import Counter
from utils import merge_dicts
from functools import wraps
from operator import itemgetter
import tldextract
import json
import publicsuffix

class Service(object):
    """Class for grouping extracted domains and other elements under one service-related umbrella.
    
    A service has a name at a bare minimum, has a hit counter, and can be extended to contain any other
    data that would be relevant (e.g., usernames and passwords).
    """
    def __init__(self, name, description=None, category=None, domains=[], hits=0):
        self.name = name
        self.description = description
        self.category = category      
        self.hits = hits
    
    def __repr__(self):
        return """Service('%s')""" % self.name    
    
    def __hash__(self):
        return hash(self.name+self.description+self.category)
        
    def __eq__(self, other):
        if not other.category or not self.category:
            return self.name == other.name
        else:
            return self.name == other.name and self.category == other.category
        
    def __add__(self, other):
        if self == other:
            return Service(self.name, description=self.description, \
                           category=self.category, hits=self.hits+other.hits)
        else:
            raise TypeError('You cannot combine two Service instances that are for different services.')          

class Domain(Service):
    """A Domain is a Service without any identifying info. Kind of a placeholder right now."""
    def __init__(self, name, hits=None):
        super(Domain, self).__init__(name, hits)

    def __repr__(self):
        return "Domain('%s')" % self.name    
        
class Email(tuple):
    
    """
    Internal representation of an email address, which contains the address portion, 
    a parsed domain, and the plaintext.
    
    Email(plaintext) --> Email(address, domain, plaintext)"""
    
    __slots__ = ()
    _fields = ('address', 'host', 'plaintext')
    
    def __new__(_cls, plaintext):
        host = tldextract.extract(plaintext)
        
        # Very basic check... the rest should be taken care of by the regexes already.
        if '@' not in plaintext:
            raise ValueError("This doesn't look like a valid email address.")
        address = plaintext.split('@')[0]
        return tuple.__new__(_cls, (address, host, plaintext))

    def __repr__(self):
        return "Email(address=%s, host=%s, plaintext=%s)" % self

    address = property(itemgetter(0))
    host = property(itemgetter(1))
    plaintext = property(itemgetter(2))
        
class ServiceMap(object):
    """Allows you to map domain names to service names."""
             
    def __init__(self):
        from serviceList import domainmap
        
        self.domainmap = domainmap
        self.process_map()
        
    def process_map(self):
        self.SERVICE_MAP = {}
        self.service_names = {}
        
        # Create a new domain where each element of the tuple is now its own key pointing to
        # the same service name. 
        for domainlist, servicename in self.domainmap.items():
            for domainkw in domainlist:
                self.SERVICE_MAP[domainkw] = servicename
        
        # And create a new dictionary for name --> domain lookup.        
        self.service_names = {v:k for k, v in self.domainmap.items()}    
        
        # And create the TLD validation list    
        self.psl = [suffix.s for suffix in publicsuffix.public_suffix_list()]

    def fromdomain(self, domain, hits=0):
        """Returns a service given a stripped domain name, or a Domain if the mapping is nonexistent."""
        from serviceList import mapping
        
        try:
            name = self.SERVICE_MAP[domain]
        except KeyError:
            name = False
        if name in mapping:
            return mapping[name] + Service(name, hits=hits) 
        else:
            return Domain(domain, hits=hits)
    
    def fromname(self, service_name):
        """Returns a tuple of service domains given a name, or False if nonexistent."""
        try: 
            return self.service_names[service_name]
        except KeyError:
            return False

class LeakResults(object):
    """Holds the JSON export for processing (for now.)"""
    def __init__(self, outfile):
        with open(outfile) as f:
            self.leaks = json.load(f)
        self.processed = {}
        self.map = ServiceMap()
                        
        # A list of trace outputs relevant to different areas of interest.
        self.relevant_keys = {
            'domains': ['visited-subdomains', 'private-browsing','https-servers'],
            'email': ['email'],
            'services': ['visited-subdomains', 'private-browsing','https-servers', 'html-titles'],
            'system': ['os', 'browser']
        }
        # Analysis pipeline (not automatically executed yet)
        self.analyses = [self.domainparsing, self.countservices, self.domainstoservices, self.emailvalidation]
        
    def pipeline(func):
        """Wrapper function for all the operations in the data processing pipeline.
        When used via the @pipeline decorator, self.temp will automatically be initialized
        pre-processing and merged with the self.processed dictionary post-processing.
        """
        @wraps(func)
        def wrapped(self, *args, **kwargs):
            # temporary dictionary
            self.temp = {} 
            # call the function to do the processing
            func(self, *args, **kwargs)
            # merge temporary and processed dicts 
            self.processed = merge_dicts(self.processed, self.temp)    
        return wrapped
    
    @pipeline
    def emailvalidation(self):
        """Removes unhelpful email-like strings from the email list (e.g. 'icon@2xresolution.png')."""
        for k in self.available_keys('email'):
            self.temp[k] = [Email(addr) for addr in self.leaks[k] if Email(addr).host.suffix in self.map.psl]

    @pipeline
    def domainparsing(self):
        """Parses all the domains into a (plaintext, ExtractResult) tuple."""
        for k in self.available_keys('domains'):
            self.temp[k] = [(domain, tldextract.extract(domain)) for domain in self.leaks[k]]
            
    @pipeline
    def countservices(self):
        """Produces a 'hit count' from browsing history."""
        for k in self.available_keys('domains'):
            self.temp[k] = Counter(domain[1] for domain in self.processed[k])

    @pipeline
    def domainstoservices(self): 
        """Turns browsing history into a list of Services""" 
        for k in self.available_keys('domains'):
            assert type(self.processed[k]) == Counter
            self.temp[k + "-svc"] = [self.map.fromdomain(domain.domain, hits=count) for domain, count in self.processed[k].items()]
    
    def available_keys(self, category):
        """Return the overlap between the available keys (data you have) and all relevant
        keys (data that you want)."""
        return set(self.relevant_keys[category]) & set(self.leaks.keys())
            
    def analyze(self):
        """Runs all the analyses and then merges the newly analyzed data with the original data."""
        # run the analysis list
        [function() for function in self.analyses]
        
        # merge intermediates with original dictionary
        merge_dicts(self.processed, self.leaks)
            
        
    pipeline = staticmethod(pipeline)    


def genservice(name, hits=None):
    """Returns a Service if information on it already exists, otherwise a name."""
    from serviceList import mapping as services

    if name in services:
        return services[name] + Service(name, hits=hits) 
    else:
        return Domain(name, hits=hits)    