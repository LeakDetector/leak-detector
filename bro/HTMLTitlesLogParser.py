from collections import defaultdict
from BroLogParser import BroLogParser
from xml.sax.saxutils import unescape 

class HTMLTitlesLogParser(BroLogParser):
    
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
        "---": "&mdash;",
    }
    html_unescape_table = {v:k for k, v in html_escape_table.items()}

    stop_titles = [
        '',
        'AddThis utility frame',
        'Ads by Quigo',
        'Quigo TPP - v1.2',
        'Disqus Comments',
        'Twitter Widgets IFRAME Event Hub',
        'Twitter Tweet Button',
        'Redirecting...',
        '301 Moved Permanently',
        '302 Found'
    ]

    def __init__(self, log_path):
        super(HTMLTitlesLogParser, self).__init__(log_path)
    
    def __display_title(self, title):
        """Simple heuristics to decide if a page title is noise or not"""
        if title in self.stop_titles: return False
        elif len(title) > 25 and ' ' not in title: return False
        else: return True

    def _process_record(self, r):
        title = unescape(r['title'], self.html_unescape_table)
        if self.__display_title(title):
            self.data['html_titles'].add(title)
