import re
import logging
from xml.sax.saxutils import unescape

class HTMLAnalyzer(object):

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
    ]
    
    def __init__(self, html):
        self.page_titles = set()
        self.amazon_products= set()
        
        logging.getLogger(__name__).info('    Analyzing HTML...')
        self.__extract_title(html)
        self.__extract_amazon_info(html)  #TODO: only do this if we know the page is from Amazon


    # Simple heuristics to decide if a page title is noise or not
    def __display_title(self, title):
        if title in self.stop_titles: return False
        elif len(title) > 25 and ' ' not in title: return False
        else: return True


    def __extract_title(self, html):
        title_match = re.search(r'< *title *>(.*)< */title *>', html)
        if title_match:
            title = unescape(title_match.group(1).strip(' \n\r'), self.html_unescape_table)
            #title = unescape(html.split('<title>')[1].split('</title>')[0], self.html_unescape_table)
            logging.getLogger(__name__).info('        Title: %s', title)
            if self.__display_title(title):
                self.page_titles = self.page_titles | {title}
            else:
                logging.getLogger(__name__).info('        Rejected title: %s', title)

    def __extract_amazon_info(self, html):
        # Look for an Amazon product
        prod_match = re.search(r'< *span *id *= *"btAsinTitle" *>(.*)< */span *>', html)
        if prod_match:
            product = prod_match.group(1)
            logging.getLogger(__name__).info('        Product: %s', product)

            # Look for the vendor
            vendor_match = re.search(r'< *span *>[ \n]*by&#160; *< *a *href *= *".*" *>(.*)< */a *>[ \n]*< */span *>', html)
            if vendor_match:
                product = '%s [Vendor: %s]' % (product, vendor_match.group(1))

            # Look for the price
            price_match = re.search(r'< *span *id *= *"actualPriceValue" *>< *b *class *= *"priceLarge" *>(.*)< */b *>< */span *>', html)
            if price_match:
                product = '%s  [Price: %s]' % (product, price_match.group(1))
            
            self.amazon_products = self.amazon_products | {product}
