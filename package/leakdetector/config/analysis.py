import re

#from config import apis
import apis
from ..userdata import productinfo

# A list of trace outputs relevant to different areas of interest.
relevant_keys = {
    'domains': ['visited-subdomains', 'private-browsing','https-servers'],
    'personal-info': ['phone', 'http-usernames', 'http-passwords', 'personal-email'],
    'services': ['visited-subdomains', 'private-browsing','https-servers', 'html-titles'],
    'system': ['os', 'browser', 'location'],
    'forms': ['formdata'],
    'cookies': ['cookies'],
    'misc': ['html-titles', 'http-queries'],
    'names': ['welcome', 'hi'],
    'private-browsing': ['private-browsing'],
    'email': [ 'email-activity', 'email-activity-generic', 'email'],
    'files': ['files'],
    '_no_process': ['http-usernames', 'http-passwords', 'os', 'browser', 'email-activity-generic', 'email-activity']
}

# settings for _processqueries
query_ignore_domains = ['fls-na', 'fls', 'files', 'img', 'images']
query_keywords = ["q", 
                "kwd", 
                "search", 
                "search_query", # YouTube 
                "find_desc", 
                "st", 
                "_nkw", # eBay 
                "field-keywords",
                "utmdt" # Google Analytics]

# Remove 'noisy' domains such as JS CDNs, 
exclude_suffix = ['s3.amazonaws.com', 'googleapis.com', 'in-addr.arpa', '', 'rackcdn.com']

extractors = {
    "wiki": 
        {'type': 'regex',
        'scope': 'wikipedia.org', 
        'regex': re.compile("/wiki/(?<!Special:)(.+)$"), 
        'attribute': 'queries'},
    "ebay": 
        {'type': 'regex',
        'scope': 'ebay.com', 
        'regex': re.compile(r'/itm/(?:.+)/([0-9]{12})'), 
        'attribute': 'products',
        'further': productinfo.Ebay(apis.EBAY_API_KEY).idlookup},
    "amazon": 
        {'type': 'regex',
        'scope': 'amazon.com',   
        'regex': re.compile(r"(?:/|a=|dp|gp/product)([a-zA-Z0-9]{10})"), 
        'attribute': 'products',
        'further': productinfo.Amazon(apis.AMAZON_API_KEY).asinlookup},
    "southwest":
        {'type': 'formdata',
        'scope': 'southwest.com',
        'attribute': 'queries',
        'keys': ["originAirport", "returnAirport", "destinationAirport", "outboundDateString", "returnDateString", "outboundTrip", "inboundTrip"]},
    "united":
        {'type': 'formdata',
        'scope': 'united.com',
        'attribute': 'queries',
        'keys': ["$Booking$", "$Result$", "hdnAccountNumber"],
        'exact': False},
    "delta":
        {'type': 'formdata',
        'scope': 'delta.com',
        'attribute': 'queries',
        'keys': ["getPredictiveCities.dwr"],
        'exact': False}

}
