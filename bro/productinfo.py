import pickle
import requests
import bottlenose
from BeautifulSoup import BeautifulSoup
from userdata import Product

class Amazon(object):
    def __init__(self, apisettings):
        self.amazonAPI = bottlenose.Amazon(Parser=BeautifulSoup)
        with open(apisettings, "r") as f:
            APIsettings = pickle.load(f)
        self.amazonAPI.__dict__ = APIsettings    
        
    def asinlookup(self, asin):
        is_asin = re.compile("[a-zA-Z0-9]{10}").match
        if is_asin(asin) and len(asin) == 10:
            item = self.amazonAPI.ItemLookup(ItemId=asin, ResponseGroup="ItemAttributes")
            if not item.find('error'):
                itemattr = lambda tag: item.find(tag).text
                attrtags = ['title', 'formattedprice', 'brand']
                name, price, vendor = [itemattr(attr) for attr in attrtags]
                category = "%s > %s" % (itemattr('binding'), itemattr('productgroup'))
                return Product(name, price=price, vendor=vendor, description=category)
            else:
                return False
        else:
            raise ValueError("%s is not a valid ASIN (must be alphanumeric and ten characters long)." % asin)
                
class Ebay(object):
    def __init__(self, apikey):
        self.apikey = apikey
        self.endpoint = "http://open.api.ebay.com/shopping?callname=GetSingleItem&responseencoding=XML&appid=%s&siteid=0&version=515&ItemID=" % self.apikey
        
    def idlookup(self, eid):
        """Look up an eBay auction by item ID (the long numerical string in a URL)."""
        item = BeautifulSoup(requests.get(self.endpoint + eid).text)
        itemattr = lambda tag: item.find(tag).text
        
        attrtags = ['title', 'convertedcurrentprice', 'primarycategoryname', 'galleryurl']
        name, price, description, image = [itemattr(attr) for attr in attrtags]
        return Product(name, price=price, description=description, image=image, vendor="eBay")
