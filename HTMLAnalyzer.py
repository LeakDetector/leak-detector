from utils import *

class HTMLAnalyzer(object):
    
    def __init__(self, html):
        self.page_titles = set()
        
        dprint('    Analyzing HTML...')
        if '<title>' in html:
            title = html.split('<title>')[1].split('</title>')[0]
            dprint('        Title: %s' % title)
            self.page_titles = self.page_titles | {title}
