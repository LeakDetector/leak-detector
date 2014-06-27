import requests
from collections import namedtuple

TPLRule = namedtuple("TPLRule", ["prefix", "domain", "substring"])

def processtpl(url):
    """Process a raw Tracking Protection List [see http://msdn.microsoft.com/en-us/library/ie/hh273399(v=vs.85).aspx]
    into a useful list of domains and URIs of sites associated with advertisers, trackers, etc.
    """
    global TPLRule
    
    # Grab the list
    raw_list = requests.get(url).content.splitlines()    

    # Remove all lines that start with things we don't want (e.g. exceptions)
    ruletypes = ['-d', '-'] # domain or substring rules are what we want
    pl = [line.split(" ") for line in raw_list if True in map(line.startswith, ruletypes)]
    
    for rule in pl:
        prefix = rule[0]
        if prefix == '-d':
            domain = rule[1]
            substring = rule[2] if len(rule) == 3 else None
        elif prefix == "-":
            domain = None
            substring = rule[1]
        else:
            raise ValueError("Unsupported tracker listing %s in rule list." % rule)    
        yield TPLRule(prefix, domain, substring)

def main(url, filename):
    """Downloads and pickles a TPL list."""
    try:
        import cPickle as pickle
    except:
        import pickle
    global TPLRule
    
    # Generate the list of rules
    rules = list(processtpl(url))
    with open(filename, 'w') as output:
        pickle.dump(rules, output)
    output.closed    
    
    print "Generated file %s." % filename
        
if __name__ == '__main__':
    URL = 'https://easylist-msie.adblockplus.org/easyprivacy.tpl'
    filename = "trackers.dat"
    main(URL, filename)
