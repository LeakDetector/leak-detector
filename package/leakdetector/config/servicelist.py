from ..userdata.userdata import Service

# A manually generated start. 
mapping = {
    'Facebook': {"category": "Social network"},
    'Google': {"category": "Search engine"},
    'Twitter': {"category": "Social network"},
    'YouTube': {"category": "Video sharing"},
    'Amazon': {"category": "Shopping"},
    'New York Times': {"category": "News"},
    'Google Analytics': {"category": "Tracking/advertising"},
    'eBay': {"category": "Shopping"},
    'Wikipedia': {"category": "Reference"},
    'Gmail': {"category": "Email"}
}

# A few basic examples for a method to translate various domains
# and subdomains to one common, readable "owner".
domainmap = {('fbcdn', 'facebook', 'fbstatic', 'fbexternal'): 'Facebook',
     ('googleusercontent',
      'google',
      'gstatic',
      'googlesyndication',
      'ggpht',
      'googletagservices', 'googleapps', 'googleapis', '1e100', 'googlecommerce'): 'Google',
     ('twimg', 'twitter'): 'Twitter',
     ('youtube', 'ytimg', "youtu"): 'YouTube',
     ('amazon', 'amazonsupply', 'images-amazon', 'amazonlocal', 'ssl-images-amazon', 'a9'): 'Amazon',
     ('nytimes', 'nyt', 'nyti', 'nytstore', 'nytco'): 'New York Times',
     ('google-analytics', 'googleanalytics'): 'Google Analytics',
     ('gmail'): 'Gmail',
     ('ebay', 'ebaystatic', 'ebaypartnernetwork'): 'eBay',
     ('wikipedia', 'wikimedia'): 'Wikipedia'
 }