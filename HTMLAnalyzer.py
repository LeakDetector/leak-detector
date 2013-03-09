import re
from utils import *

class HTMLAnalyzer(object):
    
    def __init__(self, html):
        self.page_titles = set()
        self.amazon_products= set()
        
        dprint('    Analyzing HTML...')
        self.__extract_title(html)
        self.__extract_amazon_info(html)  #TODO: only do this if we know the page is from Amazon


    def __extract_title(self, html):
        if '<title>' in html:
            title = html.split('<title>')[1].split('</title>')[0]
            dprint('        Title: %s' % title)
            self.page_titles = self.page_titles | {title}

    def __extract_amazon_info(self, html):
        # Look for an Amazon product
        prod_match = re.search(r'< *span *id *= *"btAsinTitle" *>(.*)< */span *>', html)
        if prod_match:
            product = prod_match.group(1)
            dprint('        Product: %s' % product)

            # Look for the vendor
            vendor_match = re.search(r'< *span *>[ \n]*by&#160; *< *a *href *= *".*" *>(.*)< */a *>[ \n]*< */span *>', html)
            if vendor_match:
                product = '%s [Vendor: %s]' % (product, vendor_match.group(1))

            # Look for the price
            price_match = re.search(r'< *span *id *= *"actualPriceValue" *>< *b *class *= *"priceLarge" *>(.*)< */b *>< */span *>', html)
            if price_match:
                product = '%s  [Price: %s]' % (product, price_match.group(1))
            
            self.amazon_products = self.amazon_products | {product}
