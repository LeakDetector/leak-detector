from collections import defaultdict
import re

# Leak detector specific
import productinfo
from ..config import analysis
from ..utils import findformdata

class ExtractSiteStructuredData(object):
    """Base class for all extractors."""
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
    """Extractor that grabs terms from a site URL using a regular expression,
    with the option to further process the extracted term."""
    
    def __init__(self, scope, attr, re, further=None):
        self.scope = scope # term we're searching for
        self.attr = attr # name for target attribute
        self.re = re     # extractor regex
        if further:
            # Further processing function
            self.further = further 
        else:
            # Have it exist for the sake of laziness (so we can always call it)
            self.further = (lambda i: i)
        
    def process(self, parent, data):
        """Process the extracted data and add to relevant domain."""
        
        if "LeakResults" not in str(parent.__class__):
            raise TypeError("`parent` must be a LeakResults object.")

        matches = self.re.findall(data)
        
        if matches:

            # Grab the relevant extracted term
            item = self.further(matches[0]) if type(matches) in [list, tuple] else self.further(matches)
            # Has that term been recorded on this domain yet?
            existing = parent.finditem(parent.leaks['combined'], self.scope)    
            ts = parent.findtimestamp(data)
            
            if not hasattr(existing, self.attr): 
                # If not, create the set to hold matches
                setattr(existing, self.attr, set())
            # Add it
            if hasattr(item, 'name') and getattr(item, 'name') != 'Not Found':
                if item not in [match[0] for match in getattr(existing, self.attr)]:
                    getattr(existing, self.attr).add((item, ts)) 

class SiteFormData(ExtractSiteStructuredData):
    """Extractor that grabs values from recorded site form data given
    certain keys, with the option to further process the term."""
    
    def __init__(self, scope, attr, keys, exact=True, further=None):
        self.scope = scope # On what domain?
        self.attr = attr   # What kind of data is this?
        self.keys = keys   # What form data are we searching for?
        self.exact = exact # Exact key matches or substrings?
        if further:
            self.further = further 
        else:
            self.further = (lambda i: i)

    def process(self, parent, target):
        """
        Process extracted data and append to relevant domain or service.
        
        parent --> LeakResults object
        target --> Domain object list
        """
        
        if "LeakResults" not in str(parent.__class__):
            raise TypeError("`parent` must be a LeakResults object.")
        
        attrinfo = defaultdict(set)
        
        for key in self.keys:
            # Look for relevant form data
            matches = findformdata(target, key, exact=self.exact, limit=lambda i: i == self.scope)
            if matches and self.exact:
                the_match = tuple(reduce(list.__add__, matches[key]))
                # Add the match
                attrinfo[key].add(self.further(the_match))
            elif matches:
                # Add all the matches, even partial
                for k, v in matches.items():
                    the_match = tuple(reduce(list.__add__, v))
                    attrinfo[k].add(self.further(the_match))
            # Find domain/service object        
            existing = parent.finditem(parent.leaks['combined'], self.scope)
            # Add information 
            if not hasattr(existing, self.attr): 
                setattr(existing, self.attr, attrinfo)        
                
class ExtractorRegistry(object):
    _types = {'base': ExtractSiteStructuredData, 'form': SiteFormData, 'uri-regex': SiteURIRegex}
    
    """Wrapper class to serve as a 'smart' dictionary to store
    extractors.  Supports __getitem__, get, register."""
    
    msg_badtype = "All extractors must be derived from the base class."
    
    def __init__(self, _list):
        if any(not issubclass(type(ex), ExtractSiteStructuredData) for ex in _list):
            raise TypeError(self.msg_badtype)
            
        self._list = _list
        self._extractors = defaultdict(list)
        for ex in self._list:
            self._extractors[ex.scope].append(ex)
        
    def __getitem__(self, item):
        # Slight workaround for defaultdict...
        if item in self._extractors:
            ex = self._extractors[item]
            if type(ex) is list and len(ex) == 1:
                return ex[0]
            else:
                return ex    
        else:
            raise KeyError("%s" % item)    
    
    def __str__(self):
        return "%s - %s" % (self.__class__, self._list)
    
    def get(self, item):
        """Get a specific domain's extractor."""
        return self.__getitem__(item)    
        
    def getall(self, _type):
        """Get all extractors of a certain type."""
        if _type in self._types.keys():
            return [i for i in self._list if type(i) == self._types[_type] ]
        else:
            raise ValueError("%s is an unsupported type. Currently available: %s" % (_type, ', '.join(self._types.keys()) ))
        
    def register(self, extractor):
        """Register a new extractor."""
        if not issubclass(type(extractor), ExtractSiteStructuredData):
            raise TypeError(self.msg_badtype)
        self._list.append(extractor)    
        self._extractors[extractor.scope].append(extractor)
        
    def sites(self):
        """List of all the extractors' domains."""
        return self._extractors.keys()
    
    def extractors(self):
        """List of all extractors."""
        return reduce(list.__add__, self._extractors.values())                
                
                
def newextractor(properties, **kwargs):
    """Extractor factory that reads a dictionary of properties
    and returns a new class."""
    
    if properties['type'] == 'regex':
        further = properties.get('further') or (lambda i: i)    
        return SiteURIRegex(properties['scope'], properties['attribute'], properties['regex'], further=further, **kwargs)
    elif properties['type'] == 'formdata':
        exact = properties.get('exact') or True
        further = properties.get('further') or (lambda i: i)    
        return SiteFormData(properties['scope'], properties['attribute'], properties['keys'], exact=exact, further=further, **kwargs)    
    else:
        raise TypeError

def genextractors():
    """Returns a registry of all extractors defined in the configuration
    file `config.analysis.extractors`."""
    
    extractorlist = [newextractor(props) for props in analysis.extractors.values()]            
    return ExtractorRegistry(extractorlist)

