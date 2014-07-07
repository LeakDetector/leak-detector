from collections import Counter, namedtuple
from utils import merge_dicts
from functools import wraps
from alchemyapi import alchemyapi
from cookies import Cookies
from google_analytics_cookie import *
from BeautifulSoup import BeautifulSoup 

import inspect
import tldextract
import json
import itertools
import re
import productinfo
import urlparse

try:
    import cPickle as pickle
except ImportError:
    import pickle    
    
from userdata import *

        
class ServiceMap(object):
    """Allows you to map domain names to service names."""
             
    def __init__(self):
        from serviceList import domainmap
        self.domainmap = domainmap        
        self.process_map()
        self._init_product()
    
    def _init_product(self):
        # Product lookup APIs. Currently supports eBay and Amazon.
        self.ebayAPI = productinfo.Ebay("CMUHCII7a-a7be-484f-8f81-d600d641438")    
        self.amazonAPI = productinfo.Amazon("includes/amazon-api.dat")
        
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
        
        # And open the TLD validation list (for email validation)
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
    
    # For categorization; AlchemyAPI allows 1K hits/day
    ALCHEMY_API_KEY = "48980ef6932f3393a5a3059021e9645857cc3c12"
    
    def __init__(self, outfile):
        with open(outfile) as f: self.leaks = json.load(f)
        self.processed = {}
        self.map = ServiceMap()
                        
        # A list of trace outputs relevant to different areas of interest.
        self.relevant_keys = {
            'domains': ['visited-subdomains', 'private-browsing','https-servers'],
            'personal-info': ['email', 'phone', 'http-usernames', 'http-passwords'],
            'services': ['visited-subdomains', 'private-browsing','https-servers', 'html-titles'],
            'system': ['os', 'browser'],
            'forms': ['formdata'],
            'cookies': ['cookies'],
            'misc': ['html-titles', 'http-queries'],
            'names': ['welcome', 'hi']
        }
        
        # Analysis pipeline 
        self.analyses = [self._emailvalidation, self._domainparsing, 
                    self._countservices, self._domainstoservices, 
                    self._processhttpinfo, self._combine, 
                    self._processcookies, 
                    self._processformdata]
                    
    def __getitem__(self, key):
        try:
            return self.processed[key]
        except KeyError:
            return self.leaks[key]    
    
    def finditem(self, l, item):
        return l[l.index(item)]
            
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
    def _emailvalidation(self):
        """Removes unhelpful email-like strings from the email list (e.g. 'icon@2xresolution.png')."""
        for k in ['email']:
            self.temp[k] = [Email(addr) for addr in self.leaks[k] if Email(addr).host.suffix in self.map.psl]

    @pipeline
    def _domainparsing(self):
        """Parses all the domains into a (plaintext, ExtractResult) tuple."""
        for k in self.available_keys('domains'):
            self.temp[k] = [(domain, tldextract.extract(domain)) for domain in self.leaks[k]]
            
    @pipeline
    def _countservices(self):
        """Produces a 'hit count' from browsing history."""
        for k in self.available_keys('domains'):
            self.temp[k] = Counter(domain[1] for domain in self.processed[k])

    @pipeline
    def _domainstoservices(self): 
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
    def _processhttpinfo(self):
        """Extract unsecure HTTP requests into parsed (domain, uri) tuples."""
        self.temp['http-queries'] = [(tldextract.extract(data[0]), data[1]) for data in self.leaks['http-queries']]

    @pipeline
    def _processformdata(self):
        """Move form data into a more structured format."""
        for k in self.available_keys('forms'):
            self.temp[k] = [Form(data) for data in self.leaks[k]]
            
        # Append to domain/service    
        for form in self.temp['formdata']:
            domain = str(form.host.registered_domain)
            if domain in self.leaks['combined']:
                item = self.finditem(self.leaks['combined'], domain)
                if not hasattr(item, "formdata"): item.formdata = []
                item.formdata.append(form)
            
    @pipeline
    def _combine(self):
        """Combine all the separate instances of domains and services into one condensed list."""
        self.leaks['combined'] = list(set(reduce(list.__add__, 
                                 [self.processed['service-'+k] for k in self.available_keys('domains')
                                 if 'private-browsing' not in k] )))
                   
    @pipeline
    def _processcookies(self):
        """Extract cookies into their own data type and then process relevant ones."""
        
        # future: extract info per service (i.e. United flight searches)
        self.temp['cookies'] = []
        # Extract cookies into key-value format
        for domain, cdata in self.leaks['cookies']:
            try:
                container = Cookies.from_request("Cookie: %s" % cdata, ignore_bad_cookies=True)
                container.domain = tldextract.extract(domain)
                self.temp['cookies'].append(container)
            except:
                # Some sites have cookies that are apparently VERY not up to spec
                continue
                
        # Analyze google analytics cookies
        ga_cookies = [c for c in self.temp['cookies'] if "__utma" in c]
        relevant_cookies = []
        for cookie in ga_cookies:
            gatime = GoogleAnalyticsCookie(utma=cookie['__utma'].value).utma
            relevant_cookies.append((cookie.domain, gatime['first_visit_at'], gatime['previous_visit_at']))
            
            for domain, first, prev in set(relevant_cookies):
                if domain in self.leaks['combined']:
                    item = self.finditem(self.leaks['combined'], domain)
                    item.first_visit = first
                    item.prev_visit = prev
                    
    @pipeline                
    def _processqueries(self):
        """Extract searches/queries from request strings and then process queries to get
        data on known sites (e.g. Amazon)."""
        self.temp['queries'] = []
        self.temp['queries-by-site'] = {}
        
        # Regexes for known sites
        amazon_asin = re.compile(r"(/|a=|dp|gp/product)([a-zA-Z0-9]{10})") 
        ebay_item = re.compile(r'/itm/(.+)/([0-9]{12})')
        wiki_page = re.compile("/wiki/(?<!Special:)(.+)$")
        
        # Exclude some domains (like autocomplete servers)
        excluded = ['fls-na', 'fls', 'files', 'img', 'images']
        filter_keywords = ["q", "kwd", "search"]
        site_matching = { 
            "wikipedia.org": wiki_page,
            "ebay.com": ebay_item,
            "amazon.com": amazon_asin 
        }
        
        # Build list of queries to further process
        interesting_queries = []
        for domain, uri in self.leaks['http-queries'] :
            qs = urlparse.parse_qs(uri)
            if any(key in qs for key in filter_keywords):
                interesting_queries.append((domain, qs))
                                
        # Standalone findings: for example, a search term
        # (google.com/search?q=blah)
        for domain, qs in interesting_queries:
            # Find the appropriate query string to look for and extract term
            queryvar = [var for var in filter_keywords if var in qs][0]
            searchterm = qs[queryvar]
            if type(searchterm) is list: searchterm = searchterm[0]
            
            # If there's already recorded information about this domain/service
            # then add the search term to its information
            if domain.registered_domain in self.leaks['combined']:
                item = self.finditem(self.leaks['combined'], domain.registered_domain)
                if not hasattr(item, "queries"): item.queries = set()
                item.queries.add(searchterm)
                
            self.temp['queries'].append( (domain, searchterm) )

        # Process further: for example, get the product info from an Amazon ASIN
        interesting_sites = [(domain, uri) for domain, uri in self.leaks['http-queries'] 
                                if any(key == domain.registered_domain for key in site_matching.keys())]

        for domain, uri in interesting_sites:
            # Grab the appropriate regex term extractor 
            matches = re.compile(site_matching[domain.registered_domain]).findall(uri)
            
            if matches and (domain.subdomain not in excluded and domain.domain not in excluded):
                # Handle things by service
                if domain.registered_domain == 'amazon.com': # lookup by ASIN
                    product = self.map.amazonAPI.asinlookup(matches[0][1])
                    amazon = self.finditem(self.leaks['combined'], "Amazon")
                    if not hasattr(amazon, "products"): amazon.products = set()
                    amazon.products.add(product)
                elif domain.registered_domain == 'ebay.com': # lookup by ebay ID 
                    product = self.map.ebayAPI.idlookup(matches[0][1])
                    ebay = self.finditem(self.leaks['combined'], "eBay")
                    if not hasattr(ebay, "queries"): ebay.products = set()
                    ebay.products.add(product)
                elif domain.registered_domain == 'wikipedia.org':
                    article = matches[0][1]
                    wiki = self.finditem(self.leaks['combined'], "Wikipedia")
                    if not hasattr(wiki, "queries"): wiki.queries = set()
                    wiki.queries.add(article)
                else:    
                    item = self.finditem(self.leaks['combined'], domain.registered_domain)
                    if not hasattr(item, "queries"): item.queries = set
                    item.queries.add(matches[0])
                    
                if domain.registered_domain not in self.temp['queries-by-site']:
                    self.temp['queries-by-site'][domain.registered_domain] = []
                self.temp['queries-by-site'][domain.registered_domain].append( (domain, matches) )
                
            # Also a chance to integrate page titles?

    def _prep_export(self):

        # Dict to store data for export           
        self.info = {
            'services': [svc for svc in combined if type(svc) == Service],
            'domains': [dom for dom in combined if type(svc) == Domain],
            'private-browsing': self.leaks['service-private-browsing'],
            'system': {k:self.leaks[k] for k in self.available_keys('system')},
            'personal-info': {k:self.leaks[k] for k in self.available_keys('personal-info')},
            'queries-and-searches': [self.leaks['queries'], self.leaks['queries-by-site']],
            'other': {k:self.leaks[k] for k in self.available_keys('other')}

        }

        
        
    # @pipeline
    # def _categorize(self):
    #     self.api = alchemyapi.AlchemyAPI(self.ALCHEMY_API_KEY)
    #     categorize_url = lambda query: self.api.taxonomy("url", query)
    #     results = [
    #         categorize_url(url) for url in []
    #     ]
        
    def available_keys(self, category):
        """Return the overlap between the available keys (data you have) and all relevant
        keys (data that you want)."""
        return set(self.relevant_keys[category]) & set(self.leaks.keys())
            
    def analyze(self):
        """Runs all the analyses and then merges the newly analyzed data with the original data."""
        # run the analysis list
        [function() for function in self.analyses]
        
        # merge intermediates with original dictionary
        self.leaks = merge_dicts(self.leaks, self.processed)
        
    pipeline = staticmethod(pipeline)    