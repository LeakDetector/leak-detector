from utils import *

class UserStats(object):

    def __init__(self):
        self.os = ''
        self.languages = set()
        self.browsers = set()
        self.visited_domains = set()
        self.visited_subdomains = set()
        self.page_titles = set()

    def update_os(self, os):
        self.os = os

    def update_languages(self, languages):
        self.languages = self.languages | languages

    def update_browsers(self, browsers):
        self.browsers = self.browsers | browsers

    def update_visited_domains(self, domains):
        self.visited_domains = self.visited_domains | domains

    def update_visited_subdomains(self, subdomains):
        self.visited_subdomains = self.visited_subdomains | subdomains

    def updated_page_titles(self, titles):
        self.page_titles = self.page_titles | titles
    
    # TODO: move this somewhere
    def update_from_html(self, html):
        dprint('    Searching HTML...')
        if '<title>' in html:
            title = html.split('<title>')[1].split('</title>')[0]
            dprint(title)
            self.page_titles = self.page_titles | {title}
        


    def __str__(self):
        str_ = """The following data is available to anyone on your network:
GENERAL
  OS: %(os)s
  Language: %(languages)s
  Browsers: %(browsers)s

VISITED DOMAINS\n %(visited_domains)s

VISITED PAGES\n %(page_titles)s""" % self.__dict__
        return str_
