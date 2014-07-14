# Builtins
from collections import Counter, namedtuple
from functools import wraps
import json
import itertools
import re
import urlparse
import logging

# Third party
from includes.google_analytics_cookie import *
from includes.cookies import Cookies
from BeautifulSoup import BeautifulSoup 

import includes.tldextract as tldextract
import requests

# Leak detector specific
import config.custom
from servicemapper import *
from userdata.userdata import *
from utils import merge_dicts

logging.basicConfig(level=logging.DEBUG)

class LeakResults(object):
    """
    Represents a network activity dump in JSON format outputted by `leakdetector.py`.
    Contains further processing functions.
    """
        
    def __init__(self, outfile):
        self.logger = logging.getLogger('LeakResults')                
    
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
        self.analyses = [
                    self._emailvalidation, self._domainparsing, 
                    self._countservices, self._domainstoservices, 
                    self._processhttpinfo, self._combine, 
                    self._processcookies, self._processformdata, 
                    self._processqueries, self._remove_duplicates,
                    self._categorize_infrastructure,
                    self._categorize_existing
        ]
                    
    def __getitem__(self, key):
        try:
            return self.processed[key]
        except KeyError:
            return self.leaks[key]    
    
    def finditem(self, l, item, domains=False):
        """Find a specific item in the list of domains and services."""
        
        if domains:
            return [svc for svc in l if item in svc.domains[0]][0]
        else:    
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
        self.logger.info("Processing email addresses.")
        for k in ['email']:
            self.temp[k] = [Email(addr) for addr in self.leaks[k] if Email(addr).host.suffix in self.map.psl]

    @pipeline
    def _domainparsing(self):
        """Parses all the domains into a (plaintext, ExtractResult) tuple."""
        self.logger.info('Processing web activity logs (1/2).')
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
        self.logger.info('Processing web activity logs (2/2).')
        
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
        self.logger.info('Processing form data.')
        
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
        
        self.logger.info('Processing domain data...')
        # Combine duplicates
        nodup = list(set(reduce(list.__add__, 
                                 [self.processed['service-'+k] for k in self.available_keys('domains')
                                 if 'private-browsing' not in k] )))
                                 
        # And combine subdomains                         
        bydomain = sorted( [i for i in nodup if not type(i) is Service], 
                            key=lambda s: s.domains[0].domain )
        # Add all services by default
        combined = [i for i in nodup if type(i) is Service]                    
                            
        for name, domains in itertools.groupby(bydomain, lambda s: s.domains[0].domain):
            domains = list(domains)
            if len(domains) > 1:
                self.logger.debug("COMBINE_GROUP %s" % name)
                # Collapse domain list
                domainlist = reduce(list.__add__, [i.domains for i in domains])
                # Add up hits
                hits = sum([i.hits for i in domains])
                # Find the service with the most info.
                mostinfo = max(domains, key=lambda i: len(i.__dict__.keys()) ) 
                # New name will be the most basic name
                name = mostinfo.domains[0].registered_domain
                # Combine all the separate subdomains under one base domain
                basedomain = Domain(None)
                calculated_keys = ['domains', 'hits', 'name']
                basedomain_dict = dict( {'domains': domainlist, 'hits': hits, 'name': name},
                                    **{k:v for k, v in mostinfo.__dict__.items() if k not in calculated_keys} )
    
                # Dict transplant
                basedomain.__dict__ = basedomain_dict
                combined.append(basedomain)
            else:
                # Just add the existing thing
                self.logger.debug("COMBINE_ADD %s" % name)
                combined.append(domains[0])    
        
        self.leaks['combined'] = combined           
        
    @pipeline
    def _processcookies(self):
        """Extract cookies into their own data type and then process relevant ones."""
        
        self.logger.info('Processing cookie data.')
        
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
        
        self.logger.info('Extracting search queries and product information.')
        
        # self.temp['queries'] = []
        # self.temp['queries-by-site'] = {}
        
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
        for domain, uri in self.processed['http-queries']:
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
                
#            self.temp['queries'].append( (domain, searchterm) )

        # Process further: for example, get the product info from an Amazon ASIN
        interesting_sites = [(domain, uri) for domain, uri in self.processed['http-queries'] 
                                if any(key == domain.registered_domain for key in site_matching.keys())]

        for domain, uri in interesting_sites:
            # Grab the appropriate regex term extractor 
            matches = re.compile(site_matching[domain.registered_domain]).findall(uri)
            
            if matches and (domain.subdomain not in excluded and domain.domain not in excluded):
                # Handle things by service and tag relevant item
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
                    
                # if domain.registered_domain not in self.temp['queries-by-site']:
                #     self.temp['queries-by-site'][domain.registered_domain] = []
                # self.temp['queries-by-site'][domain.registered_domain].append( (domain, matches) )
                
            # Also a chance to integrate page titles?

    @pipeline
    def _categorize_infrastructure(self):
        """Categorize non-services such as trackers and CDNs."""
        
        # All present tracking services that are a simple domain match
        self.logger.info('Processing information on tracking websites..')
        
        presentdomains = set(reduce(list.__add__, [d.domains for d in self.leaks['combined']]))
        domainmatches = list(self.map.trackers['domain-rules'] & presentdomains)
        for domain in domainmatches:
            # Set flag
            self.finditem(self.leaks['combined'], domain).tracking = True

        # If any requests match the substring rules
        for trackerdomain, regex in self.map.trackers['substring-rules']:
            for domain, uri in self.processed['http-queries']:
                domain_and_uri_match = ( trackerdomain and trackerdomain == domain and regex.findall(uri) )
                uri_match = (not trackerdomain and regex.findall(uri))
                if domain_and_uri_match or uri_match:
                    # Set flag
                    self.finditem(self.leaks['combined'], domain).tracking = True
                    
        # Categorize CDN domains and remove individual domains
        present_cdns = list(set([d for d in self.map.cdns if d in self.leaks['combined']]))
        for cdn in present_cdns:
            name = self.map.cdns[cdn]
            svc = Service(name=name, category=["Web", "Content Distribution Network"], domains=cdn)
            self.leaks['combined'].append(svc)
        for cdn in present_cdns: self.leaks['combined'].remove(cdn)

    @pipeline
    def _categorize_existing(self):
        """Attempt to categorize domains using data from various sources."""
        
        # first pass - top 500 sites from Alexa
        self.logger.info('Categorizing web activity - pass 1/5 (top 500 sites).')
        available = list( 
                    set(tldextract.extract(svc.name).registered_domain for svc in self.leaks['combined'] if not svc.category) \
                    & set(self.map.top500.keys()) )
        for sitename in available:
            self.finditem(self.leaks['combined'], sitename).category = self.map.top500[sitename]
            
        # second/third pass - DMOZ data  
        # main database
        self.logger.info('Categorizing web activity - pass 2/5 (DMOZ open web directory).')
        self.map.categorize_dmoz(self.leaks['combined'], self.map.dmoz)
                
        # world/regional sites database
        self.logger.info('Categorizing web activity - pass 3/5 (DMOZ open web directory).')
        self.map.categorize_dmoz(self.leaks['combined'], self.map.world_dmoz)
        self.map.categorize_dmoz(self.leaks['combined'], self.map.regional_dmoz)
            

    # @pipeline
    def _categorize_lookup(self):
        """Categorize sites using AlchemyAPI."""
        
        def extract_meta(url):
            page = BeautifulSoup(requests.get("http://"+url).content)
            tags = ['og:description', 'description', 'keywords', 'og:keywords']
            for prop in tags:
                content = page.find('meta', {'property': prop} )
                if content:
                    return (prop, content['content'])
                    
        needscategory = {tldextract.extract(svc.name).registered_domain:svc 
                        for svc in self.leaks['combined'] if svc.category is None}
        
        self.logger.info('Categorizing web activity - pass 4/5 (webpage meta tags)')
        for domain, service in needscategory.items():
            cat = extract_meta(domain)
            if not cat is None:
                if 'keywords' in cat[0]:
                    self.finditem(self.leaks['combined'], domain).category = cat
                else:
                    self.finditem(self.leaks['combined'], domain).description = cat
                
        # fifth pass - automatic categorization by alchemyAPI NLP service
        # Try to categorize based on base domain
        self.logger.info('Categorizing web activity - pass 5/5 (AlchemyAPI natural language processing service).')
        needscategory = {tldextract.extract(svc.name).registered_domain:svc 
                        for svc in self.leaks['combined'] if svc.category is None}
        n = len(needscategory.keys())                
        
        self.logger.debug( "%s items need categorizing, which will probably take around %s seconds." % (n, .75*n) )
                        
        for domain, service in needscategory.items():
            cat = self.map.categorize_url(domain)
            self.finditem(self.leaks['combined'], domain).category = cat
        
    @pipeline        
    def _remove_duplicates(self):
        """Remove duplicate sites and combine based on subdomain."""
        
        self.logger.info("Removing duplicates and combining...")        
        
        # Services with the same domain name but different subdomains/suffixes
        # with the base domain already categorized 
        # (e.g. google.com, google.com.hk, google.es, google.co.br...)
        # redundant_cats = [i for i in self.leaks['combined'] if not i.category
        #     and self.finditem(self.leaks['combined'], i.domains[0].domain, domains=True).category]
        
        # Remove irrelevant listings, DNS stuff
        exclude_suffix = ['s3.amazonaws.com', 'googleapis.com', 'in-addr.arpa', '']
        exclude = [i for i in self.leaks['combined'] if i.domains[0].suffix in exclude_suffix]
        
        for dup in exclude: self.leaks['combined'].remove(dup)
        
    
    def _prep_export(self):
        # Dict to store data for export           
        self.info = {
            'services': [svc for svc in combined if type(svc) == Service],
            'domains': [dom for dom in combined if type(svc) == Domain],
            'private-browsing': self.leaks['service-private-browsing'],
            'system': {k:self.leaks[k] for k in self.available_keys('system')},
            'personal-info': {k:self.leaks[k] for k in self.available_keys('personal-info')},
            'other': {k:self.leaks[k] for k in self.available_keys('other')}

        }
        
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
    
if __name__ == '__main__':
    raise NotImplementedError('Please run from a Python shell while under development.')    