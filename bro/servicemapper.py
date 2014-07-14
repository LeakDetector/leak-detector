import logging
try:
    import cPickle as pickle
except ImportError:
    import pickle    

from includes.alchemyapi import alchemyapi
from includes.sqlitedict import SqliteDict
import includes.tldextract as tldextract

import config.apis
import config.files
import productinfo
from userdata.userdata import *

class ServiceMap(object):
    """Container for lookup and processing functions that relate domains, services, etc. to
    relevant information.
    
    Currently:
        * Domain name to service
        * Product lookup from product ID
        * Tracking website lookup
        * AlchemyAPI categorizer
    
    """
    def __init__(self):
        self.logger = logging.getLogger("ServiceMap")
        
        from config.servicelist import domainmap
        self.domainmap = domainmap        
        self.process_map()
        self.init_product()
        self.init_categorizer()
        
    def init_product(self):
        """Initialize product lookup APIs."""
        # Product lookup APIs. Currently supports eBay and Amazon.
        self.ebayAPI = productinfo.Ebay(config.apis.EBAY_API_KEY)    
        self.amazonAPI = productinfo.Amazon(config.apis.AMAZON_API_KEY)
    
    def init_categorizer(self):
        """Initialize access to categorization databases."""
        # Alexa top 500 sites
        with open(config.files.TOP500_LIST) as f: self.top500 = pickle.load(f)
        
        # AlchemyAPI natural language processing API
        self.alchemyAPI = alchemyapi.AlchemyAPI(config.apis.ALCHEMY_API_KEY)
        
        # Open web directory data
        self.dmoz = SqliteDict(config.files.SITE_CATEGORIES['main'])
        self.regional_dmoz = SqliteDict(config.files.SITE_CATEGORIES['regional-us'])
        self.world_dmoz = SqliteDict(config.files.SITE_CATEGORIES['world'])
        
        # List of CDN domains
        with open(config.files.CDN_LIST) as f: self.cdns = pickle.load(f)
        
        # Tracking/analytics websites
        with open(config.files.TRACKER_LIST, 'rb') as f: self.trackers = pickle.load(f)
    
    def process_map(self):
        """Process hardcoded service-to-info maps."""
        self.SERVICE_MAP = {}
        self.service_names = {}
        
        # Create a new domain where each element of the tuple is now its own key pointing to
        # the same service name. 
        for domainlist, servicename in self.domainmap.items():
            for domainkw in domainlist:
                self.SERVICE_MAP[domainkw] = servicename
        
        # And create a new dictionary for name --> domain lookup.        
        self.service_names = {v:k for k, v in self.domainmap.items()}    
        
        # And open the TLD validation list (for email validation):
        with open(config.files.PSL) as f: self.psl = pickle.load(f)
        
    def categorize_url(self, query):
        """Categorize a URL using AlchemyAPI given a certain URL."""
        
        self.logger.debug("CATEGORIZE: trying to categorize %s" % query)
        results = self.alchemyAPI.taxonomy("url", query)
        status = results['status']
        if status == "OK":
            taxonomy = results['taxonomy']
            if taxonomy:
                taxonomy = taxonomy[0]
                self.logger.debug("CATEGORIZE: <%s> -- <%s>" % (query, taxonomy) )
                return (taxonomy['label'], taxonomy['score'])
            else:
                return ("Other", 1.0)    
        else:
            self.logger.debug("CATEGORIZE: %s - %s - %s" % (status, query, results['statusInfo']) )
            self.logger.debug("CATEGORIZE: %s <%s>" % (results['status'], query) )
            
    def categorize_dmoz(self, sitelist, dmoz):
        """Categorize a list of sites given a list of Services or Domains
        and a dictionary mapping base domains to categories.  
        
        Returns None, updates in place."""
        
        # Basic checks
        if type(dmoz) not in [dict, SqliteDict]:
            raise TypeError("Please provide a dictionary-like object for lookups.")
            
        assert type(sitelist) is list
        
        for svc in sitelist:
            assert type(svc) in [Service, Domain]
            
            category = svc.category
            domain = tldextract.extract(svc.name).registered_domain  
            try:
                dmozinfo = dmoz[domain]
                if not category: # If it's not already categorized
                    self.logger.debug('CATEGORIZE DMOZ %s [domain %s] --> %s' % (svc.name, domain, dmozinfo))
                    svc.category = dmozinfo['category']
                    svc.name = dmozinfo['name']
            except:
                # Doing "if domain in dmozinfo" would be better, but this is such a large
                # database that takes more time than a try/except block to just catch errors
                continue
            
    def fromdomain(self, domain, hits=0):
        """Returns a service given a stripped domain name, or a Domain if the mapping is nonexistent."""
        
        from config.servicelist import mapping
        
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
            svc = Service(name, category=category, hits=hits) 
            svc.add_domain(domain)
            return svc
        else:
            dom = Domain(name, hits=hits)
            dom.add_domain(domain)
            return dom
    
    def fromname(self, service_name):
        """Returns a tuple of service  given a name, or False if nonexistent."""
        try: 
            return self.service_names[service_name]
        except KeyError:
            return False
            