import json
import pprint
import tldextract
import urlparse
from operator import itemgetter
from collections import defaultdict

class UserData(object):
    def __init__(self, data={}):
        self.data = data
        self.output_filter = []

    def merge(self, userdata):
        for k, v in userdata.data.iteritems():
            if k in self.data:
                if type(v) is set:
                    self.data[k] = list(self.data[k] or v)
                elif type(v) is list:
                    self.data[k] += v
            else:
                if type(v) is set: 
                    #import pdb; pdb.set_trace()
                    self.data[k] = list(v)
                else:    
                    self.data[k] = v

    def set_output_filter(self, filter_string):
        '''supply a CSV string of data tags to include in output'''
        self.output_filter = filter_string.strip().split(',')

    def __get_filtered_output(self):
        if self.output_filter:
            return {key: self.data[key] for key in self.output_filter if key in self.data}
        else:
            return self.data
    filtered_output = property(__get_filtered_output)

    def __str__(self):
        return pprint.pformat(self.filtered_output)

    def __to_json(self):
        return json.dumps(self.filtered_output)
    json = property(__to_json)
    
class Service(object):
    """Class for grouping extracted domains and other elements under one service-related umbrella.
    
    A service has a name at a bare minimum, has a hit counter, and can be etended to contain any other
    data that would be relevant (e.g., usernames and passwords).
    """
    def __init__(self, name, description=None, category=None, domains=None, hits=0):
        self.name = name
        self.description = description
        self.category = category      
        self.hits = hits
        if domains: 
            self.domains = [domains]
        else:
            self.domains = []    
    
    def __repr__(self):
        return "Service(%s)" % ", ".join(["%s=%s"%(k,v) for k, v in self.__dict__.items()])
        
    def __str__(self):
        return "Service --> %s" % self.__dict__
    
    def __hash__(self):
        return hash("%s%s%s"%(self.name, self.description, self.category))
        
    def __eq__(self, other):
        """Equal if: same name, string with same name as service, domains are equal."""
        
        if type(other) is Service:
            if not other.category or not self.category:
                return self.name == other.name
            else:
                return self.name == other.name and self.category == other.category
        elif type(other) in [str, unicode]:
            samename = (other == self.name)
            samedomain = other in [d.registered_domain for d in self.domains]
            samefulldomain = other in [d.subdomain + d.registered_domain for d in self.domains]
            return samename or samedomain or samefulldomain
        elif type(other) is Domain:
            if other.domains:
                overlap = set([d.registered_domain for d in other.domains]) \
                        & set([d.registered_domain for d in self.domains])
                if overlap: 
                    return True
                else:
                    return False    
            else:
                return False    
        elif type(other) is tldextract.ExtractResult:
            if self.domains:
                return  other.registered_domain in [d.registered_domain for d in self.domains]
            else:
                return False    
        
    def __add__(self, other):
        import copy
        if self == other:
            attrs = copy.copy(self.__dict__)
            attrs['hits'] = self.hits + other.hits
            attrs['domains'] = list(self.domains) + list(other.domains)
            newsvc = Service(self.name)
            newsvc.__dict__ = attrs
            return newsvc
        else:
            raise TypeError('You cannot combine two Service instances that are for different services.')          
    
    def add_domain(self, domain):
        self.domains.append(domain)        

class Domain(Service):
    """A Domain is a Service without any identifying info. Kind of a placeholder right now."""
    def __init__(self, name, domains=[], hits=None):
        super(Domain, self).__init__(name, domains=domains, hits=hits)

    def __repr__(self):
        return "Domain(%s)" % ", ".join(["%s=%s"%(k,v) for k, v in self.__dict__.items()])
        
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

class Form(tuple):
    """
    Internal representation of form data. Parses a (domain, uri, querystring) tuple
    into a host, uri, and form-data-dict tuple.
    """
    
    __slots__ = ()
    _fields = ('host', 'uri', 'data')
    
    def __new__(_cls, plaintext):
        host = tldextract.extract(plaintext[0])
        uri = plaintext[1]
        rawdata = plaintext[2]
        
        # Reconstruct the full URL for urlparse
        full_url = url = "http://%s%s?%s" % (plaintext[0], uri, rawdata)
        data = urlparse.parse_qs(full_url)

        return tuple.__new__(_cls, (host, uri, data))

    def __repr__(self):
        return "Form(host=%s, uri=%s, data=%s)" % self

    host = property(itemgetter(0))
    uri = property(itemgetter(1))
    data = property(itemgetter(2))
    
class Product(object): 
    def __init__(self, name, price=None, description=None, vendor=None, image=None):
        self.name = name
        self.price = price
        self.description = description
        self.vendor = vendor
        self.image = image
        
    def __hash__(self):
        return hash(self.__repr__())    
    
    def __getitem__(self, key):
        if hasattr(self, key):
            return getattr(self, key)
            
    def __add__(self, other):
        if self == other and self.description == other.description and self.price == other.price:
            return self

    def __repr__(self):
        return "Product(%s)" % ", ".join(["%s=%s"%(k,v) for k, v in self.__dict__.items()])

    def __eq__(self, other):
        if type(other) is Product:
            return self.name == other.name
        elif type(other) is str:
            return self.name == other