from userdata.userdata import Service

# Just a place to store the mappings right now. 
# For the future, I'll probably make this JSON or something and autogenerate the mapping to classes.
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

# A list of trace outputs relevant to different areas of interest.
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