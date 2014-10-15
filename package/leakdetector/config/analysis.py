import re

from config import apis
from userdata import productinfo

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
query_keywords = ["q", "kwd", "search", "search_query", "find_desc", "st", "_nkw", "field-keywords"]
                                            # youtube                       # ebay

# structured data extraction
extractors = {
    "wiki": 
        {'type': 'regex',
        'scope': 'wikipedia.org', 
        'regex': re.compile("/wiki/(?<!Special:)(.+)$"), 
        'attribute': 'pages'},
    "ebay": 
        {'type': 'regex',
        'scope': 'ebay.com', 
        'regex': re.compile(r'/itm/(.+)/([0-9]{12})'), 
        'attribute': 'products',
        'further': productinfo.Ebay(apis.EBAY_API_KEY)},
    "amazon": 
        {'type': 'regex',
        'scope': 'amazon.com',   
        'regex': re.compile(r"(/|a=|dp|gp/product)([a-zA-Z0-9]{10})"), 
        'attribute': 'products',
        'further': productinfo.Amazon(apis.AMAZON_API_KEY).asinlookup},
    "southwest":
        {'type': 'formdata',
        'scope': 'southwest.com',
        'attribute': 'flights',
        'keys': ["originAirport", "returnAirport", "destinationAirport", "outboundDateString", "returnDateString", "outboundTrip", "inboundTrip"]},
    "united":
        {'type': 'formdata',
        'scope': 'united.com',
        'attribute': 'flights',
        'keys': ["$Booking$", "$Result$", "hdnAccountNumber"],
        'exact': False},
    "delta":
        {'type': 'formdata',
        'scope': 'delta.com',
        'attribute': 'flights',
        'keys': ["getPredictiveCities.dwr"],
        'exact': False}
}
