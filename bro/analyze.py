from collections import Counter
from utils import merge_dicts
import json

class Service(object):
    def __init__(self, name, description=None, category=None, domains=[], hits=None):
        self.name = name
        self.description = description
        self.category = category      
        self.hits = hits
    
    def __repr__(self):
        return "Service('%s')" % self.name    
    
    def __hash__(self):
        return hash(self.name+self.description+self.category)
        
    def __add__(self, other):
        if self.name == other.name and self.category == other.category:
            return Service(self.name, description=self.description, \
                           category=self.category, hits=self.hits+other.hits)
        else:
            raise TypeError('You cannot combine two Service instances that are for different services.')                   

class Domain(Service):
    def __init__(self, name, hits=None):
        super(Domain, self).__init__(name, hits)

    def __repr__(self):
        return "Service('s')" % self.name    
        
class ServiceMap(object):
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
        
        for domainlist, servicename in self.domainmap.items():
            for domainkw in domainlist:
                self.SERVICE_MAP[domainkw] = servicename
                
        self.service_names = {v:k for k, v in self.domainmap.items()}        

    def fromdomain(self, domain):
        try:
            service = self.SERVICE_MAP[domain]
        except KeyError:
            service = False
        finally:
            return service        
    
    def fromname(self, service_name):
        try: 
            return self.service_names[service_name]
        except KeyError:
            return False

class LeakResults(object):
    
    def __init__(self, outfile):
        with open(outfile) as f:
            self.leaks = json.load(f)
        self.processed = {}
        self.map = ServiceMap()
            
        self.relevant_keys = {
            'domains': ['visited-subdomains', 'private-browsing-domains','https-servers'],
            'email': ['email'],
            'services': ['visited-subdomains', 'private-browsing-uris','https-servers', 'html-titles'],
            'system': ['os', 'browser']
        }
        self.analyses = [self.countservices, self.getservices]
    
    def countservices(self):
        temp = {}
        for k in self.relevant_keys['domains']:            
            processed[k] = Counter(domain[-2] for domain in self.leaks[k])
        self.processed = merge_dicts(self.processed, temp)    
    
    def getservices(self):  
        temp = {}
        for k in relevant_keys['domains']:
            assert type(self.processed[k]) == Counter
            temp[k] = list()
            for domain, count in self.processed[k].items():
                name = self.map.fromdomain(domain)
                temp[k].append(genservice(name, hits=count))
            
        self.processed = merge_dicts(self.processed, temp)    
            
    def analyze(self):
        # call each analysis
        # mergedict
        pass


def genservice(name, hits=None):
    services = {
        'Facebook': Service("Facebook", category="Social network"),
        'Google': Service("Google", category="Search engine"),
        'Twitter': Service("Twitter", category="Social network"),
        'YouTube': Service("YouTube", category="Video sharing")
    }
    if name in services:
        return services[name] + Service(name, hits=hits) 
    else:
        return Domain(domain, hits=hits)    