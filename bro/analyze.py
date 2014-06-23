from collections import Counter
from utils import merge_dicts
import json

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
        
class ServiceMap(object):
    """Allows you to map domain names to service names."""
    
    # Dictionary where the key is a tuple of domains and the value is the service name.
    domainmap = {('fbcdn', 'facebook', 'fbstatic', 'fbexternal'): 'Facebook',
         ('googleusercontent',
          'google',
          'gstatic',
          'googlesyndication',
          'ggpht',
          'googletagservices', 'googleapps', 'googleapis', '1e100', 'googlecommerce'): 'Google',
         ('twimg', 'twitter'): 'Twitter',
         ('youtube', 'ytimg'): 'YouTube'}
             
    def __init__(self):
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
            'domains': ['visited-subdomains', 'private-browsing-domains','https-servers'],
            'email': ['email'],
            'services': ['visited-subdomains', 'private-browsing-uris','https-servers', 'html-titles'],
            'system': ['os', 'browser']
        }
        # Analysis pipeline (not automatically executed yet)
        self.analyses = [self.countservices, self.domainstoservices]
    
    def countservices(self):
        """Produces a 'hit count' from browsing history."""
        temp = {}
        for k in self.available_keys('domains'):
            temp[k] = Counter(domain[-2] for domain in self.leaks[k])
        self.processed = merge_dicts(self.processed, temp)    
    
    def domainstoservices(self): 
        """Turns browsing history into a list of Services""" 
        temp = {}
        for k in self.available_keys('domains'):
            assert type(self.processed[k]) == Counter
            temp[k] = [self.map.fromdomain(domain, hits=count) for domain, count in self.processed[k].items()]
            
        self.processed = merge_dicts(self.processed, temp)    
    
    def available_keys(self, category):
        """Return the overlap between the available keys (data you have) and all relevant
        keys (data that you want)."""
        return set(self.relevant_keys[category]) & set(self.leaks.keys())
            
    def analyze(self):
        # call each analysis
        # mergedict
        pass


def genservice(name, hits=None):
    """Returns a Service if information on it already exists, otherwise a name."""
    from serviceList import mapping as services

    if name in services:
        return services[name] + Service(name, hits=hits) 
    else:
        return Domain(name, hits=hits)    