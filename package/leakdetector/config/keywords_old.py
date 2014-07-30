import re
from collections import namedtuple
from types import FunctionType

class Keyword(object):
    def __init__(self, kwd, regex=None, lr_key=None, validate_with='regex', validation=None):
        # The specified keyword to search for
        self.kwd = kwd
        # Can this keyword be found in a special place already (e.g., LeakResults.processed['personal-info'])
        self.lr_key = lr_key or False 
        # What do you validate with?
        self.validate_with = validate_with
        self.matches = []
        
        # Appropriate settings based on matching method.
        if validate_with == 'regex':
            # The regular expression for matching this type of keyword
            self.regex = regex or "(%s)" % kwd 
            if basestring in type(self.kwd).mro(): self.kwd_regex = re.compile("(%s)" % self.kwd, re.IGNORECASE)
            self.compiled_re = re.compile(self.regex, re.IGNORECASE)
        elif validate_with == 'function':
            if type(validation) == FunctionType:
                self.validation_function = validation
            else:
                raise TypeError("The given validation function is not a function.")    
        else:
            raise ValueError("%s is not a supported validation scheme." % self.validate_with)    
    
    def check(self, string):
        return self.compiled_re.split(string)

    # def findall(self, string):
    #     if self.validate_with == 'regex':
    #         all_matches = self.compiled_re.findall(string)
    #         return [k for k in ["".join(match) for match in all_matches] if self.kwd_regex.match(k)]
    #     else:
    #         raise NotImplementedError("%s.findall is not implemented for non-regular-expression validation." % self.__name__)
    #
    # def split(self, string):
    #     if self.validate_with == 'regex':
    #         the_split = self.compiled_re.split(string)
    #         if any(self.kwd_regex.match(segment) for segment in the_split if segment):
    #             return the_split
    #     else:
    #         raise NotImplementedError("%s.match is not implemented for non-regular-expression validation." % self.__name__)
        

class Phone(Keyword):
    _preset_regex = \
    '(?:(?:\\+?1\\s*(?:[.-]\\s*)?)?' +\
    '(?:\\(\\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\\s*\\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\\s*' +\
    '(?:[.-]\\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\\s*' +\
    '(?:[.-]\\s*)?([0-9]{4})' +\
    '(?:\\s*(?:#|x\\.?|ext\\.?|extension)\\s*(\\d+))?'
    _phone = namedtuple("phonenumber", ['country', 'area', 'exchange', 'last4', 'extension'])

    def __init__(self, area, exchange, last4, extension=''):
        kwd = self._phone('', str(area), str(exchange), str(last4), str(extension))
        super(Phone, self).__init__(kwd, regex=self._preset_regex, lr_key='phone')
        
    def check(self, string):
        for match in self.compiled_re.findall(string):
            matched_pn = self._phone(*match)
            if matched_pn[1:4] == self.kwd[1:4] or "".join(matched_pn) in "".join(self.kwd): 
                # Phone numbers are equal (minus cc, extension)
                return [i for i in self.compiled_re.split(string) if i]
