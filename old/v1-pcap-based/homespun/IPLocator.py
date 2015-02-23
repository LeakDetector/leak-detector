import httplib
import re
import logging

class IPLocator(object):
    
    def __init__(self):
        self.__conn = httplib.HTTPConnection("www.geobytes.com")

    def locate(self, ip):
        self.__conn.request("GET", '/IpLocator.htm?GetLocation&template=php3.txt&IpAddress=%s' % ip)
        r = self.__conn.getresponse()

        if r.status != 200:
            logging.getLogger(__name__).warning('Unable to locate IP address %s', ip)
            return

        # response consists of a bunch of lines like this:
        # <meta name="city" content="Pittsburgh">
        loc = {}
        data = r.read()
        for line in data.split('\n'):
            match = re.search(r'<meta name="(.*)" content="(.*)">', line)
            if match:
                loc[match.group(1)] = match.group(2)

        if loc['city'] == 'Limit Exceeded':
            return None
        else:
            return loc
