import pickle
import requests
import bottlenose

from BeautifulSoup import BeautifulSoup
from userdata import Product

class Amazon(object):
    """An interface to Amazon's ItemLookup API."""
    
    def __init__(self, apisettings):
        # Load API settings (pickled dictionary written to a file containing API key and other settings.)
        self.amazonAPI = bottlenose.Amazon()
        try:
            with open(apisettings, "r") as f:
                APIsettings = pickle.load(f)
        except IOError, e:
            raise IOError("%s.  Please load a valid API settings file." % e) 
        APIsettings['Parser'] = BeautifulSoup
        self.amazonAPI.__dict__ = APIsettings    
        self.cache = {}
        
    def asinlookup(self, asin):
        """Look up a product via ASIN number and return a new Product object with the relevant
        details filled in.
        
        >>> amazon = Amazon("includes/amazon-api.dat")
        >>> amazon.asinlookup("B0002INQT2")
        Product(price=$69.95, vendor=Pelican, name=Pelican 1200 Case with Foam for Camera (Black), image=None, description=Electronics > Photography)
        >>>
        """
        import re
        
        # An ASIN is Amazon's universal product identifier that takes the form of a
        # ten-character alphanumeric string (e.g., B000012345X)
        is_asin = re.compile("[a-zA-Z0-9]{10}").match
        def is_asin(asin):
            tokens = ['REDIRECTIO', 'NAVIGATION', 'SESSIONCAC', 'MEMBERSHIP', 'REVIEWSGAL', 'SLREDIRECT']
            noTokens = asin.upper() not in tokens 
            begin = asin.upper()[0] in ['A', 'B', '0']
            return re.compile("[a-zA-Z0-9]{10}").match(asin) and noTokens and begin
                    
        def fetchImage(amazonAPI, asin):
            try:
                return amazonAPI.ItemLookup(ItemId=asin, ResponseGroup="Images").find('mediumimage').find('url').string
            except:
                return False               
            
        dummyProduct = Product(name='Not Found',
                                description='You viewed an Amazon product, but we were unable to match its ID in the database.')
        
        if is_asin(asin) and len(asin) == 10:
            if asin not in self.cache:
                try:
                    item = self.amazonAPI.ItemLookup(ItemId=asin, ResponseGroup="ItemAttributes")
                    itemattr = lambda tag: item.find(tag).text
                except:
                    return dummyProduct
                    
                # Response will contain an <error> tag if there is a problem
                if not item.find('error'): 
                    attrtags = ['title', 'formattedprice', 'brand']
                    name, price, vendor = [item.find(attr).text if item.find(attr) else "n/a" for attr in attrtags]
                    try:
                        category = "%s > %s" % (itemattr('binding'), itemattr('productgroup'))
                    except:
                        category = "Amazon product"
                        
                    product = Product(name, price=price, vendor=vendor, description=category, image=fetchImage(self.amazonAPI, asin))
                    self.cache[asin] = product
                    return product
                else:
                    # Since an automated process is providing the ASINs, fail silently instead of
                    # raising an exception as matches aren't guaranteed to be 100% accurate.

                    return dummyProduct
            else:
                return self.cache[asin]        
        else:
            return dummyProduct
                
class Ebay(object):
    """An interface to eBay's listing info API, specifically the GetSingleItem call.
    
    >>> ebay = Ebay("ORGNAME-APIKEY-1234567890")
    >>> ebay.idlookup("251185682624")
    Product(price=9.95, vendor=eBay, name=50 pcs YUGOSLAVIA Banknotes collection, image=http://thumbs1.ebaystatic.com/pict/2511856826248080_1.jpg, description=Coins &amp; Paper Money:Paper Money: World:Europe:Yugoslavia)
    >>>
    
    API documentation: http://developer.ebay.com/Devzone/XML/docs/Reference/ebay/GetItem.html
    """
    
    def __init__(self, apikey):
        self.apikey = apikey
        self.endpoint = "http://open.api.ebay.com/shopping?callname=GetSingleItem&responseencoding=XML&appid=%s&siteid=0&version=515&ItemID=" % self.apikey
        
    def idlookup(self, eid):
        """Look up an eBay auction by item ID (the long numerical string in a URL)."""
        item = BeautifulSoup(requests.get(self.endpoint + eid).text)
        itemattr = lambda tag: item.find(tag).text
        
        # Response contains an <Ack> tag that either reads "Success" or "Failure"
        if item.find("ack").text == "Success":
            attrtags = ['title', 'convertedcurrentprice', 'primarycategoryname', 'pictureurl']
            name, price, description, image = [item.find(attr).text for attr in attrtags]
            return Product(name, price=price, description=description, image=image, vendor="eBay")
        else:
            # Since an automated process is providing the IDs, fail silently instead of
            # raising an exception as matches aren't guaranteed to be 100% accurate.
            return False    