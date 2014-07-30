import os.path

"""Files and includes for various databases and preset lists.""" 
try:
    here = os.path.dirname(os.path.realpath(__file__))
except NameError:
    here = os.path.curdir + os.path.sep
here = os.path.join(here, "../")
    
# List of domains associated with advertisers, analytics, and tracking services.
TRACKER_LIST = os.path.join(here, "includes/site-data/tracker-rules.dat") #pickle

# Info on the top 500 sites.
TOP500_LIST = os.path.join(here, "includes/site-data/top500-sites.dat") #pickle

# Content distribution networks.
CDN_LIST = os.path.join(here, "includes/site-data/cdns.dat") #pickle

# List of email provider domains
EMAIL_LIST = os.path.join(here, "includes/email-providers.dat")

# Processed DMOZ databases for site categorization.
SITE_CATEGORIES = { #sqlitedict
    'main': os.path.join(here, 'includes/site-data/dmoz.db'),
    'regional-us': os.path.join(here, 'includes/site-data/regional_dmoz.db'),
    'world': os.path.join(here, 'includes/site-data/world_dmoz.db')
}

# Public suffix list (valid tlds)
PSL = os.path.join(here, "includes/processed-psl.dat") #pickled

# List of form data regular expressions (taken from Chrome source) to parse formdata.
FORM_REGEXES = os.path.join(here, "includes/form-data-regex.dat") #pickled

# MaxMind GeoLite2-City database 
GEOIP = os.path.join(here, "includes/GeoLite2-City.mmdb")
