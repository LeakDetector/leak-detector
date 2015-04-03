# Builtins
from collections import Counter, namedtuple, defaultdict
from functools import wraps
import simplejson as json
import itertools
import re
import urlparse
import logging

# Third party
from includes.google_analytics_cookie import *
from includes.cookies import Cookies
from BeautifulSoup import BeautifulSoup 
import tldextract
import requests

# Leak detector specific
import config.analysis
from servicemapper import *
from userdata import dataextract
from userdata.userdata import *
from utils import merge_dicts, class_register, register, findformdata

def ResultsEncoder(o):
    """
    Helper function for json.dump() that provides the serializable form
    of object `o` when passed.
    
    >>> svc = Service("example.com", description="An example website.", hits=4, domains=[tldextract.extract("example.com")])
    >>> json.dumps(svc, default=ResultsEncoder)
    {
        "category": null,
        "description": "An example website.",
        "domains": [
            [
                {
                    "domain": "example",
                    "subdomain": "",
                    "suffix": "com",
                    "tld": "com"
                }
            ]
        ],
        "hits": 4,
        "name": "example.com"
    }
    >>>
    """
    if type(o) in [Service, Domain, Product]:
        return o.__dict__
    elif type(o) is datetime:
        return o.isoformat()   
    else:
        try:
            iterable = iter(o)
        except TypeError:
            return json.JSONEncoder().default(o)    
        else:
            return list(iterable)        


@class_register
class LeakResults(object):
    
    """
    Represents a network activity dump in JSON format outputted by `leakdetector.py`.
    Contains further processing functions. 
    
    To create a new analysis function, write the function to operate on the 
    raw data in self.leaks.  If the function has any intermediary processing steps,
    decorate the function with the `@merge_processed` decorator, which will provide the
    function with a temporary dictionary `self.temp`, whose keys will be merged with the
    larger `self.processed` dictionary after the processing is finished.
    
    When you're ready to add your function to the overall pipeline, decorate it with a
    `@register(n)` decorator, which will add your function to the list of analyses. 
    
    When the `self.analyze()` function is called, all functions that have been @register-ed
    will be called in the order specified by `n` in the decorator, which means that
    you can require that functions be run in a certain order. `@register(-1)` will put the
    function at the head of the list.
    
    Overall execution flow:
        --> instantiate class with filename
            --> [all functions with @register are registered]
                --> creates `self._analyses`
        --> l.analyze() called
            --> all functions called in order `@register(-1)`... `@register(n)`
        --> processed items in self.processed merged with unprocessed items 
            --> self.finished created with all data
        --> data exported to JSON        
    """
        
    def __init__(self, outfile):
        self.logger = logging.getLogger('LeakResults')                

        # Load file
        with open(outfile) as f: self.leaks = json.load(f)
        # Empty dict for processing
        self.processed = {}
        self.finished = {}
        # Initialize container class for analysis utilities
        self.map = ServiceMap()
        # User data extractor classes
        self.extractors = dataextract.genextractors()
        # State
        self.analysis_finished = False
        
    def __getitem__(self, key):
        """Try and return a processed item; if not, then the unprocessed one."""
        try:
            return self.finished[key]
        except KeyError:
            try:
                return self.processed[key]
            except:
                return self.leaks[key]    
                
    def available_keys(self, category):
        """Overlap between relevant keys and available keys."""
        relevant = set(config.analysis.relevant_keys[category])
        available = set(self.leaks.keys() + self.processed.keys())
        return set(relevant & available)
        
    def is_available(self, key):
        """Like available_keys, but for one specific key."""
        
        if type(key) in [list, tuple]:
            return all(k in self.leaks for k in key)
        elif type(key) in [str, unicode]:    
            return key in self.leaks
        else:
            raise ValueError    
            
    def analyze(self, again=False):
        """Runs all the analyses and creates a dictionary with all of the analyzed data."""
        
        if not self.analysis_finished and not again:
            # This ungodly series of list comprehension creates 
            # a list of functions ordered in the sequence given by the decorators.
            ordered_func_list = [fname for order, fname in sorted(self._analyses.items(), key=lambda item: item[0])]
            ordered_func_list = [getattr(self, fn) for fn in reduce(list.__add__, ordered_func_list)]

            # Call all functions
            [function() for function in ordered_func_list] 
        
            # Merge intermediates with original dictionary
            self.finished = merge_dicts(self.leaks, self.processed) 
            self.analysis_finished = True
        else:
            # Don't re-analyze unless explicitly asked to
            error = "This trace has already been analyzed." +\
                     "If you want to re-run the analysis, please run analyze(again=True)."
            raise Exception(error)   
    
    def merge_processed(func):
        """Wrapper function for all the operations in the data processing merge_processed.
        When used via the @merge_processed decorator, self.temp will automatically be initialized
        pre-processing and merged with the self.processed dictionary post-processing.
        """
        # wrapped() is the actual wrapper function that will be returned
        @wraps(func) 
        def wrapped(self, *args, **kwargs):
            # temporary dictionary
            self.temp = {} 
            # call the function to do the processing
            func(self, *args, **kwargs)
            # merge temporary and processed dicts 
            self.processed = merge_dicts(self.processed, self.temp)    
        return wrapped

    def finditem(self, l, item, domains=False):
        """Find a specific item in the list of domains and services."""
        if domains:
            return [svc for svc in l if item in svc.domains[0]][0]
        else:    
            return l[l.index(item)]

    @register(-1) # Always do first
    @merge_processed
    def _copy_unprocessed(self):
        """Copy data that doesn't need further processing straight to the output."""
        self.logger.info("Skipping data categories that don't need processing.")
        
        for k in self.available_keys('_no_process'):
            self.temp[k] = self.leaks[k]
            
    @register(1)
    @merge_processed
    def _process_email(self):
        """Removes unhelpful email-like strings from the email list
        (e.g. 'icon@2xresolution.png')."""        
        key = 'email'
        
        def _handle_addr(addr):
            e = Email(addr)
            # Only accept email-like strings that have valid TLD
            if e.host.suffix in self.map.psl:
                self.temp[key].append(e)
                if _like_personal_email(e):
                    self.temp['personal-%s' % key].append(e)
                    
        def _like_personal_email(e):
            """A basic heuristic for 'important' personal email addrs."""
            is_webmail = e.host.registered_domain in self.map.emailproviders 
            is_edu = e.host.suffix == "edu"
            if is_webmail or is_edu:
                return e
                
        if self.leaks.get(key):
            for addr in self.leaks['email']:
                self.temp[key] = []
                self.temp['personal-%s'% key ] = []
                for addr in self.leaks[key]:
                    _handle_addr(addr)
                                        
    @register(1)
    @merge_processed
    def _geolocate(self):
        """Gets location of host IP."""
        
        if self.leaks.get('device-ip'):
            self.logger.info("Geolocating IP address.")
            try: 
                self.temp['location'] = self.map.geolocate(self.leaks['device-ip'])
            except Exception:
                self.temp['location'] = "Unknown"

    @register(2)
    @merge_processed
    def _domain_parsing(self):
        """Parses all the domains into a (plaintext, ExtractResult) tuple."""
        self.logger.info('Processing web activity logs (1/2).')
        for k in self.available_keys('domains'):
            self.temp[k] = [(domain, tldextract.extract(domain)) for domain in self.leaks[k]]

    @register(3)        
    @merge_processed
    def _count_services(self):
        """Produces a 'hit count' from browsing history."""
        for k in self.available_keys('domains'):
            self.temp[k] = Counter(domain[1] for domain in self.processed[k])
    
    @register(4)
    @merge_processed
    def _domains_to_services(self): 
        """Turns browsing history into a list of Services and aggregates into service/domain list.""" 
        self.logger.info('Processing web activity logs (2/2).')
        
        services_temp = {}
        for k in self.available_keys('domains'):
            # Turn raw domain names into services
            assert type(self.processed[k]) == Counter
            services_temp[k] = list()
            for domain, count in self.processed[k].items():
                svc = self.map.fromdomain(domain, hits=count)
                services_temp[k].append(svc)

        # Combine lists of services and duplicates
        for k in services_temp:
            sortedbyname = sorted(services_temp[k], key=lambda svc: svc.name)
            aggregated = itertools.groupby(sortedbyname, lambda svc: svc.name)
            self.temp["service-"+k] = [reduce(Service.__add__, records) for name, records in aggregated]
                    
    @register(4)
    @merge_processed
    def _process_httpinfo(self):
        """Extract unsecure HTTP requests into parsed (domain, uri) tuples."""        
        if self.leaks.get('http-queries'):
            self.temp['http-queries'] = []
            for domain, query, timestamp in self.leaks['http-queries']:
                # (domain, query, timestamp)
                history_point = (tldextract.extract(domain), query, timestamp)
                self.temp['http-queries'].append(history_point)
                # Time series sort
                self.temp['http-queries'].sort(key=lambda point: point[2])
                
    @register(5)            
    @merge_processed
    def _group_httpinfo(self):
        """Group HTTP requests by page heuristic."""
        def ts_difference(l):
            new_list = []
            for i, row in enumerate(l):
                row = list(row)
                if i == 0 or i==len(l)-1:
                    delta = -1
                else:
                    delta = float(l[i+1][-1]) - float(row[-1])

                row.append(delta)        
                new_list.append(row)
        
            return new_list
            
        # Add column with time delta to next request
        with_diffs = ts_difference( sorted(self.processed['http-queries'], key=lambda row: row[2]) ) 
        
        self.temp['http-queries-grouped'] = defaultdict(list)
        group_number = 0

        for is_start, values in itertools.groupby(with_diffs, lambda row: row[-1] > 3 or row[-1] == -1):
            record = list(values)
            if is_start:
                # if len(record) == 1:
                group_number += 1 
                self.temp['http-queries-grouped'][group_number].append(record[0])
                # else:
                    # raise ValueError("Start key has length not equal to one.")
            else:
                self.temp['http-queries-grouped'][group_number] += record

    @register(5)
    @merge_processed
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
        
        # Tag private browsing
        for k in self.available_keys('private-browsing'):
            for site in self.processed[k]:
                try:
                    info = self.finditem(combined, site)
                except:
                    info = False    

                if info:
                    info.maybe_private_browsing = True
                else:
                    site.maybe_private_browsing = True
                    combined.append(site)
        
        # Tag HTTPS
        if self.leaks.get('https-servers'):
            for site in self.processed['https-servers']:
                try:
                    info = self.finditem(combined, site)
                except:
                    info = False    

                if info:
                    info.secure = True
                elif not info and type(site) in [Domain, Service]:
                    site.secure = True
                    combined.append(site)
                elif not info and "tld" in str(type(site)):
                    site = self.map.fromdomain(site)
                    site.secure = True
                    combined.append(site)
        
        self.leaks['combined'] = [site for site in combined if type(site) in [Domain, Service]]

    @register(6)
    @merge_processed
    def _process_formdata(self):
        """Move form data into a more structured format."""
        self.logger.info('Processing form data.')
        
        # TODO: Use form-data-regex.dat as a method of automatically parsing
        # forms according to browser auto-fill rules.
        
        if self.available_keys('forms'):
            for k in self.available_keys('forms'):
                self.temp[k] = [Form(data) for data in self.leaks[k]]
            
            # Append to domain/service    
            for form in self.temp['formdata']:
                domain = str(form.host.registered_domain)
                if domain in self.leaks['combined']:
                    item = self.finditem(self.leaks['combined'], domain)
                    if not hasattr(item, "formdata"): item.formdata = []
                    item.formdata.append(form)
                    
            # Process formdata with extractors
            interesting_forms = list( set(f.host.registered_domain for f in self.temp['formdata']) &\
                                      set(ex.scope for ex in self.extractors.getall('form')) )
            
            for site in interesting_forms:
                extractor = self.extractors.get(site)
                self.logger.debug("FORM %s" % extractor)
                if extractor: extractor.process(self, self.leaks['combined'])

    @register(7)
    @merge_processed
    def _process_cookies(self):
        """Extract cookies into their own data type and then process relevant ones."""
        
        self.logger.info('Processing cookie data.')
        
        self.temp['cookies'] = []
        # Extract cookies into key-value format
        if self.leaks.get('cookies'):
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

    @register(7)
    @merge_processed                
    def _process_queries(self):
        """Extract searches/queries from request strings and then process queries to get
        data on known sites (e.g. Amazon)."""
        
        self.logger.info('Extracting search queries and product information.')
        
        # Exclude some domains (like autocomplete servers with noisy data)
        excluded = config.analysis.query_ignore_domains
        filter_keywords = config.analysis.query_keywords
        
        # Build list of queries to further process
        interesting_queries = []
        if not self.leaks.get('http-queries'): return
        for domain, uri, ts in self.processed['http-queries']:
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
                
        # Process further: for example, get the product info from an Amazon ASIN
        
        # All domains recorded if they also appear in the list of sites with extractors

        interesting_sites = [(domain, uri) for domain, uri, ts in self.processed['http-queries'] 
                                if any(ex.scope == domain.registered_domain for ex in self.extractors.getall('uri-regex'))]

        for domain, uri in interesting_sites:
            # Grab the appropriate extractor class
            extractors = self.extractors.get(domain.registered_domain)
            not_excluded = (domain.subdomain not in excluded and domain.domain not in excluded)

            if extractors and not_excluded:
                # Handle things by service and tag relevant item
                if type(extractors) is list:
                    # Could be a list...
                    for ex in extractors:
                        ex.process(self, uri)
                else:
                    # Or just a single extractor
                    extractors.process(self, uri)
                    
    @register(8)
    @merge_processed
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
            match = False
            for d in self.leaks['combined']:
                if trackerdomain in d.domains: match = True 
            
            if self.leaks.get('http-queries'):
                for domain, uri, ts in self.processed['http-queries']:
                    domain_and_uri_match = ( trackerdomain and trackerdomain == domain and regex.findall(uri) )
                    uri_match = (not trackerdomain and regex.findall(uri))
                    if domain_and_uri_match or uri_match: match = True

            if match:
                self.finditem(self.leaks['combined'], domain).tracking = True
                    
        # Categorize CDN domains and remove individual domains
        present_cdns = list(set([d for d in self.map.cdns if d in self.leaks['combined']]))
        for cdn in present_cdns:
            name = self.map.cdns[cdn]
            svc = Service(name=name, category=["Web", "Content Distribution Network"], domains=cdn)
            self.leaks['combined'].append(svc)
        for cdn in present_cdns: self.leaks['combined'].remove(cdn)
    
    @register(9)
    @merge_processed
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
            

    # @merge_processed
    # @register(10)
    # TODO: Find a better solution; passing on this right now because AlchemyAPI is incredibly
    # inaccurate so far.
    # def _categorize_lookup(self):
    #     """Categorize sites using AlchemyAPI."""
    #
    #     def extract_meta(url):
    #         page = BeautifulSoup(requests.get("http://"+url).content)
    #         tags = ['og:description', 'description', 'keywords', 'og:keywords']
    #         for prop in tags:
    #             content = page.find('meta', {'property': prop} )
    #             if content:
    #                 return (prop, content['content'])
    #
    #     needscategory = {tldextract.extract(svc.name).registered_domain:svc
    #                     for svc in self.leaks['combined'] if svc.category is None}
    #
    #     self.logger.info('Categorizing web activity - pass 4/5 (webpage meta tags)')
    #     for domain, service in needscategory.items():
    #         cat = extract_meta(domain)
    #         if not cat is None:
    #             if 'keywords' in cat[0]:
    #                 self.finditem(self.leaks['combined'], domain).category = cat
    #             else:
    #                 self.finditem(self.leaks['combined'], domain).description = cat
    #
    #     # fifth pass - automatic categorization by alchemyAPI NLP service
    #     # Try to categorize based on base domain
    #     self.logger.info('Categorizing web activity - pass 5/5 (AlchemyAPI natural language processing service).')
    #     needscategory = {tldextract.extract(svc.name).registered_domain:svc
    #                     for svc in self.leaks['combined'] if svc.category is None}
    #     n = len(needscategory.keys())
    #
    #     self.logger.debug( "%s items need categorizing, which will probably take around %s seconds." % (n, .75*n) )
    #
    #     for domain, service in needscategory.items():
    #         cat = self.map.categorize_url(domain)
    #         self.finditem(self.leaks['combined'], domain).category = cat

    @register(11)
    @merge_processed        
    def _remove_duplicates(self):
        """Remove duplicate sites and combine based on subdomain."""
        
        self.logger.info("Removing duplicates and combining...")        
        
        # Services with the same domain name but different subdomains/suffixes
        # with the base domain already categorized 
        # (e.g. google.com, google.com.hk, google.es, google.co.br...)
        # redundant_cats = [i for i in self.leaks['combined'] if not i.category
        #     and self.finditem(self.leaks['combined'], i.domains[0].domain, domains=True).category]
        
        # Remove irrelevant listings, DNS stuff
        exclude_suffix = config.analysis.exclude_suffix
        exclude = [i for i in self.leaks['combined'] if i.domains[0].suffix in exclude_suffix]
        
        for dup in exclude: self.leaks['combined'].remove(dup)
        
    
    def _prep_export(self):
        """Put everything that we want in self._export."""
        
        # Dict to store data for export     
        combined = self.finished['combined']
        
        # TODO: These categories are pretty arbitrary for right now. 
        self._export = {
            'services': [svc for svc in combined if type(svc) == Service],
            'history': {'domains': [dom for dom in combined if type(dom) == Domain],
                        'page-titles': self.finished.get('html-titles'),
                        'raw-history': sorted(self.leaks.get('http-queries'), key=lambda entry: float(entry[2])),
                        'grouped-history': self.finished.get('http-queries-grouped')},
            'email': {k:self.finished[k] for k in self.available_keys('email')},
            'files': {k:self.finished[k] for k in self.available_keys('files')},
            'system': {k:self.finished[k] for k in self.available_keys('system')},
            'personal-info': {k:self.finished[k] for k in self.available_keys('personal-info')}
        }
    
    def export(self, outfile, _format='json'):
        """Export the contents of self._export to `outfile` using format `_format`."""
        _valid_formats = ['json', 'python']
        
        self.logger.info("Exporting processed results to %s." % outfile)
        self._prep_export()

        with open(outfile, 'w') as f:
            if _format == 'json':
                json.dump(self._export, f, default=ResultsEncoder)
            elif _format == 'python':
                try: 
                    import cPickle as pickle
                except:
                    import pickle    
                pickle.dump(self._export, f)
            else:
                raise ValueError("%s is not a valid export file format. Currently supported: %s" % (_format, _valid_formats))    
                
    merge_processed = staticmethod(merge_processed)    

def main(infile, outfile, verbose=False):
    """Run analysis framework."""
    
    # Set logging verbosity
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)    
        
    # just stop if it's empty
    with open(infile) as f: 
        if not len(json.load(f)): 
            return
            
    # Instantiate class around file to be processed.
    leaks = LeakResults(infile)
    # Analyze
    leaks.analyze()
    # Export
    leaks.export(outfile)
                