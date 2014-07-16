import re
# A list of trace outputs relevant to different areas of interest.
relevant_keys = {
    'domains': ['visited-subdomains', 'private-browsing','https-servers'],
    'personal-info': ['email', 'phone', 'http-usernames', 'http-passwords', 'email-activity'],
    'services': ['visited-subdomains', 'private-browsing','https-servers', 'html-titles'],
    'system': ['os', 'browser'],
    'forms': ['formdata'],
    'cookies': ['cookies'],
    'misc': ['html-titles', 'http-queries'],
    'names': ['welcome', 'hi'],
    'private-browsing': ['private-browsing'],
    '_no_process': ['http-usernames', 'http-passwords', 'os', 'browser']
}

# settings for _processqueries
query_ignore_domains = ['fls-na', 'fls', 'files', 'img', 'images']
query_keywords = ["q", "kwd", "search", "search_query", "find_desc", "st", "_nkw"]
                                            # youtube                       # ebay

sites_to_extractors = { 
    "wikipedia.org": re.compile("/wiki/(?<!Special:)(.+)$"), # non-meta wikipedia pages
    "ebay.com": re.compile(r'/itm/(.+)/([0-9]{12})'), # ebay item_id
    "amazon.com": re.compile(r"(/|a=|dp|gp/product)([a-zA-Z0-9]{10})") # amazon ASIN
}
