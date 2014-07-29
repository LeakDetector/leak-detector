import os.path
"""API keys for various services used for the application."""

try:
    here = os.path.dirname(os.path.realpath(__file__))
except NameError:
    here = os.path.curdir + os.path.sep
here = os.path.join(here, "../")

# Product lookup
EBAY_API_KEY = "CMUHCII7a-a7be-484f-8f81-d600d641438"
AMAZON_API_KEY = os.path.join(here, "includes/amazon-api.dat") # file location

# Categorization/NLP
ALCHEMY_API_KEY = "48980ef6932f3393a5a3059021e9645857cc3c12" # allows 1k hits per day
