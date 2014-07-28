"""Files and includes for various databases and preset lists."""

# List of domains associated with advertisers, analytics, and tracking services.
TRACKER_LIST = "includes/site-data/tracker-rules.dat" #pickle

# Info on the top 500 sites.
TOP500_LIST = "includes/site-data/top500-sites.dat" #pickle

# Content distribution networks.
CDN_LIST = "includes/site-data/cdns.dat" #pickle

# List of email provider domains
EMAIL_LIST = "includes/email-providers.dat"

# Processed DMOZ databases for site categorization.
SITE_CATEGORIES = { #sqlitedict
    'main': 'includes/site-data/dmoz.db',
    'regional-us': 'includes/site-data/regional_dmoz.db',
    'world': 'includes/site-data/world_dmoz.db'
}

# Public suffix list (valid tlds)
PSL = "includes/processed-psl.dat" #pickled

# List of form data regular expressions (taken from Chrome source) to parse formdata.
FORM_REGEXES = "includes/form-data-regex.dat" #pickled

# MaxMind GeoLite2-City database 
GEOIP = "includes/GeoLite2-City.mmdb"
