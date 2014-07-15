# TODO: Turn Alexa top 500 into Service()
# TODO: Grab HTML bodies from Bro and do keyword matching (or matching in bro regexes?)
# 	Provide keyword --> generate valid bro regex entry
# 					--> if type isn't just a plain keyword
# 							--> fill in appropriate spots in regex with data
# 					--> otherwise
# 							--> create generic /(term)/ regex
#	Generate table for bro script to import 
# 	Hook onto both ingoing and outgoing
# TODO: Document pipeline

import re
from collections import namedtuple

class Keyword(object):
    nkeywords = 0
    
    _formats = ["/%s/"]
    def __init__(self, kwd):
        self.kwd = kwd
        Keyword.nkeywords += 1
        
        self.varname = "$user_kwd_%s" % Keyword.nkeywords
        
    def formats(self):
        return "|".join( [ format % re.escape(self.kwd) for format in self._formats] )

class Phone(Keyword):
    _phone = namedtuple("phonenumber", ['area', 'exchange', 'last4', 'extension'])
    _formats = ["(%s) %s %s", "(%s) %s-%s", "%s %s-%s", "%s %s %s", "%s%s%s", "%s.%s.%s", "%s %s.%s", "(%s) %s.%s", "%s-%s-%s"]

    def __init__(self, area, exchange, last4, extension=''):
        kwd = self._phone(str(area), str(exchange), str(last4), str(extension))
        super(Phone, self).__init__(kwd)
        
        self.re = self.formats()

    def formats(self):
        return "/%s/" % "|".join( [re.escape(format % (self.kwd.area, self.kwd.exchange, self.kwd.last4)) for format in self._formats] )
                
class CreditCard(Keyword):
    def __init__(self, kwd):
        super(CreditCard, self).__init__(kwd)
        self.varname = "user_c"

    def formats(self):
        return "/%s|%s/" % (re.escape(self.kwd), str(re.escape(self.kwd.replace(" ", ""))))


        
        