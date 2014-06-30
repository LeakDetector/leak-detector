from collections import Counter, namedtuple
from utils import merge_dicts
from functools import wraps
from calais.base.client import Calais

import tldextract
import json
import itertools
try:
    import cPickle as pickle
except ImportError:
    import pickle    
    
from userdata import *

class Categorizer(object):
    CALAIS_KEY = "bee36xz3n48wfd6kje5k2bqu"

    def __init__(self):
        # 6/24 - coming back to this in a few days 
        raise NotImplementedError 
        self.api = Calais(CALAIS_KEY, submitter="leakdetector-dev-cmu")

    def relevant_tags(self, url):
        result = self.api.analyze_url(url)
        topicattrs = tuple(set(("topics", "relations", "languages", "entities")) & set(result.__dict__.keys()))
        
        
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
        
        # And open the TLD validation list    
        with open("includes/processed-psl.dat") as f: self.psl = pickle.load(f)

    def fromdomain(self, domain, hits=0):
        """Returns a service given a stripped domain name, or a Domain if the mapping is nonexistent."""
        from serviceList import mapping
        
        try:
            name = self.SERVICE_MAP[domain.domain]
        except KeyError:
            name = ".".join(domain)
            if name.startswith(".."): 
                name = name[2:]
            elif name.startswith("."): 
                name = name[1:]
        if name in mapping:
            category = mapping[name]['category']
            return Service(name, category=category, hits=hits, domains=domain) 
        else:
            return Domain(name, domains=domain, hits=hits)
    
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
            'system': ['os', 'browser'],
            'forms': ['formdata'],
            'cookies': ['cookies']
        }
        # Analysis pipeline 
        self.analyses = []
        
    def pipeline(func):
        """Wrapper function for all the operations in the data processing pipeline.
        When used via the @pipeline decorator, self.temp will automatically be initialized
        pre-processing and merged with the self.processed dictionary post-processing.
        """
        @wraps(func)
        def wrapped(self, *args, **kwargs):
            self.analyses.append(func)
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
        """Turns browsing history into a list of Services and aggregates into service/domain list.""" 
        services_temp = {}
        for k in self.available_keys('domains'):
            # Turn raw domains into services
            assert type(self.processed[k]) == Counter
            services_temp[k] = [self.map.fromdomain(domain, hits=count) for domain, count in self.processed[k].items()]

        # Combine lists of services and duplicates
        for k in services_temp:
            sortedbyname = sorted(services_temp[k], key=lambda svc: svc.name)
            aggregated =  itertools.groupby(sortedbyname, lambda svc: svc.name)
            self.temp["service-"+k] = [reduce(Service.__add__, records) for name, records in aggregated]
            
    @pipeline
    def processformdata(self):
        for k in self.available_keys('forms'):
            self.temp[k] = [Form(data) for data in self.leaks[k]]
            
    @pipeline
    def processcookies(self):
        for k in self.available_keys('cookies'):
            self.temp[k] = [UserCookie(data) for data in self.leaks[k]]
        
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