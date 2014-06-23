from analyze import Service

# Just a place to store the mappings right now. 
# For the future, I'll probably make this JSON or something and autogenerate the mapping to classes.

mapping = {
    'Facebook': Service("Facebook", category="Social network"),
    'Google': Service("Google", category="Search engine"),
    'Twitter': Service("Twitter", category="Social network"),
    'YouTube': Service("YouTube", category="Video sharing")
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
     ('youtube', 'ytimg'): 'YouTube'}