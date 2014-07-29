import cPickle as pickle
import tldextract
from sqlitedict import *
import urlparse

class TestWriter(object):
    def page(self, page, content):
        import pdb; pdb.set_trace()
        
class SqliteWriter(object):
    """Generates four SQLite databases containing pickle-encoded dict()
    information from a DMOZ dump.  
    
    * name.db - general sites
    * subdomains_name.db - DMOZ entries that are subdomains
    * regional_name.db - information on regional sites (US) 
    * world_name.db - information on non-US sites in a variety of languages
    
    From a fresh download, parsing takes about 10 minutes, depending on memory and
    disk write speed.
    """
    
    def __init__(self, name):
        self.dmoz = SqliteDict('./%s' % name, autocommit=False, journal_mode="OFF")
        self.sub_dmoz = SqliteDict('./subdomains_%s'%name, autocommit=False, journal_mode="OFF")
        self.regional_dmoz = SqliteDict('./regional_%s'%name, autocommit=False, journal_mode="OFF")
        self.world_dmoz = SqliteDict('./world_%s'%name, autocommit=False, journal_mode="OFF")
        
    def page(self, page, content):
        exclude_domains = ['angelfire.com', 'geocities.com', 'tripod.com', 'free.fr']
        okay_subdomains = ['www', '', ' ']
        okay_paths = ['/', '//', '/home', '/home/']
        if page:
            topic = content['topic'].split("/")[1:] if 'topic' in content else None
            if not topic: return                
            name = content['d:Title'] if 'd:Title' in content else ""
            url = tldextract.extract(page)
            urlpath = urlparse.urlparse(page)
            domain = url.registered_domain
            
            okay_sdpath = (url.subdomain in okay_subdomains or not url.subdomain) \
                            and (urlpath.path in okay_paths or not urlpath.path)
            
            siteinfo = {'name': name, 'category': topic }
            
            if urlpath.path and urlpath.path not in okay_paths:
                # Exclude specific pages listed, we just want domains
                return
            elif 'Fan_Pages' in topic or domain in exclude_domains:
                # Exclude domains
                # Fan pages: there are way too many of them.
                return
            else:
                if okay_sdpath:
                    if topic[0] == 'World': 
                        # World sites go in a separate db
                        self.world_dmoz[domain] = siteinfo
                        return
                    elif topic[0] == 'Regional':
                        self.regional_dmoz[domain] = siteinfo
                        return
                    elif url.subdomain and url.subdomain not in okay_subdomains:
                        # subdomains get a separate db
                        self.sub_dmoz[domain] = siteinfo
                        return
                    else:
                        # no subdomain or okay subdomains like www and no path
                        self.dmoz[domain] = siteinfo
                        return    
        else:
            print "Skipping page %s, page attribute is missing" % page

    def finish(self):
        print "Committing changes (1/4)..."
        self.dmoz.commit()
        self.dmoz.close()
        print "Committing changes (2/4)..."
        self.world_dmoz.commit()
        self.world_dmoz.close()
        print "Committing changes (3/4)..."
        self.regional_dmoz.commit()
        self.regional_dmoz.close()
        print "Committing changes (4/4)..."
        self.sub_dmoz.commit()
        self.sub_dmoz.close()