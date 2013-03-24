import json

class UserStats(object):

    def __init__(self):
        self.os = set()
        self.languages = set()
        self.browsers = set()
        self.visited_domains = set()
        self.visited_subdomains = set()
        self.page_titles = set()
        self.google_queries = set()
        self.amazon_products = set()
        self.email_locations = set()
        self.image_paths = set()

    def update_os(self, os):
        self.os = self.os | os

    def update_languages(self, languages):
        self.languages = self.languages | languages

    def update_browsers(self, browsers):
        self.browsers = self.browsers | browsers

    def update_visited_domains(self, domains):
        self.visited_domains = self.visited_domains | domains

    def update_visited_subdomains(self, subdomains):
        self.visited_subdomains = self.visited_subdomains | subdomains

    def update_page_titles(self, titles):
        self.page_titles = self.page_titles | titles

    def update_google_queries(self, queries):
        self.google_queries = self.google_queries | queries

    def update_amazon_products(self, products):
        self.amazon_products = self.amazon_products | products

    def update_email_servers(self, locations):
        for loc in locations.values():
            if loc:
                self.email_locations = self.email_locations | { '%s, %s (%s)' % (loc['city'], loc['region'], loc['country']) }

    def update_image_paths(self, paths):
        self.image_paths = self.image_paths | paths
    

    def __str__(self):
        str_ = """The following data is available to anyone on your network:
GENERAL
  OS: %(os)s
  Language: %(languages)s
  Browsers: %(browsers)s

GOOGLE SEARCHES\n %(google_queries)s

BROWSED AMAZON PRODUCTS\n %(amazon_products)s

EMAIL LOCATIONS\n %(email_locations)s

IMAGE PATHS\n %(image_paths)s

VISITED DOMAINS\n %(visited_domains)s

VISITED PAGES\n %(page_titles)s""" % self.__dict__
        return str_

    def to_json(self):
        info_dict = {
            'os': list(self.os),
            'languages': list(self.languages),
            'browsers': list(self.browsers),
            'visited_domains': list(self.visited_domains),
            'visited_subdomains': list(self.visited_subdomains),
            'page_titles': list(self.page_titles),
            'google_queries': list(self.google_queries),
            'amazon_products': list(self.amazon_products),
            'email_locations': list(self.email_locations),
            'image_paths': list(self.image_paths)
        }
        return json.dumps(info_dict)
    json = property(to_json)
