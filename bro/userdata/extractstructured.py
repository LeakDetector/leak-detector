from collections import defaultdict
import re

import productinfo
import config.analysis
import config.apis
from utils import findformdata

class ExtractSiteStructuredData(object):
    def __repr__(self):
        if hasattr(self, 'scope'):
            return "%s for %s on %s" % (self.__class__, self.attr, self.scope)
        else:
            return str(self.__class__)
        
    def __str__(self):
        return "%s %s" % (self.__class__, self.__dict__)
        
    def process(self, data):
        raise NotImplementedError("Please implement process() in your subclass.")

class SiteURIRegex(ExtractSiteStructuredData):
    def __init__(self, term, attr, re, further=None):
        self.term = term # term we're searching for
        self.attr = attr # name for target attribute
        self.re = re     # extractor re
        if further:      # process extracted further?
            self.further = further
        else:
            self.further = lambda i: i    
        
    def process(self, parent, data):
        assert( type(parent) == LeakResults )

        matches = self.re.findall(data)
        item = self.further(matches[0][1]) if not type(matches[0][0]) is str else self.further(matches[0])
        existing = parent.finditem(parent.leaks['combined'], self.term)    
        if not hasattr(existing, self.attr): setattr(existing, self.attr, set())
        getattr(existing, self.attr).add(item) 

class SiteFormData(ExtractSiteStructuredData):
    def __init__(self, scope, attr, keys, exact=True, further=None):
        self.scope = scope # On what domain?
        self.attr = attr   # What kind of data is this?
        self.keys = keys   # What form data are we searching for?
        self.exact = exact # Exact key matches or substrings?
        self.further = further # Further processing functions

    def process(self, parent, target):
        assert( type(parent) == LeakResults )
        attrinfo = defaultdict(set)
        
        for key in self.keys:
            matches = findformdata(target, key, exact=self.exact, limit=lambda i: i == self.scope)
            if matches and self.exact:
                attrinfo[key].append(self.further(reduce(list.__add__, matches[key])))
            elif matches:
                for k, v in matches.items():
                    attrinfo[k].append(self.further(reduce(list.__add__, v)))
            existing = parent.finditem(parent.leaks['combined'], self.scope)

            if not hasattr(existing, self.attr): 
                setattr(existing, self.attr, attrinfo)        

def newextractor(properties, **kwargs):
    if properties['type'] == 'regex':
        return SiteURIRegex(properties['scope'], properties['attribute'], properties['regex'], **kwargs)
    elif properties['type'] == 'formdata':
        exact = properties.get('exact') or True
        further = properties.get('further') or (lambda i: i)    
        return SiteFormData(properties['scope'], properties['attribute'], properties['keys'], exact=exact, **kwargs)    
    else:
        raise TypeError

def genextractors():
    return [ newextractor(props) for props in config.analysis.extractors.values() ]            
            
# amazon = newextractor(config.analysis.extractors['amazon'])
# ebay = newextractor(config.analysis.extractors['ebay'])
# wikipedia = newextractor(config.analysis.extractors['wikipedia'])
# swa = newextractor(config.analysis.extractors['southwest'])
# united = newextractor(config.analysis.extractors['united'])
# delta = newextractor(config.analysis.extractors['delta'])
#
