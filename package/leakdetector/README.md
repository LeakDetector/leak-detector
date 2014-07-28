Leak Detector (backend: bro)
============================

This is the source for the Bro-log based version of the leak detector backend.  

Third-party modules
-------------------
* Third party Python modules used are either in includes/ or specified in requirements.txt (for larger libraries).
* A few metadata files have been adapted/borrowed directly from other sources. See the LICENSE file for credits to their original authors.

Project structure
-----------------
* config/
	* analysis.py - Settings for analysis functions in analayze.py
	* apis.py - API settings
	* custom.py - User-defined/per-session settings
	* files.py - Relevant files from includes/
	* keywords.py - Architecture for user-defined keyword searches
	* servicelist.py - Domain to service mappings
* includes/
	* alchemyapi/ - AlchemyAPI natural language processing API
	* bottlenose/ - Amazon AWS API 
	* generate-site-data/ - Scripts to generate the large *_dmoz.db categorization files.
	* site-data/ - Pre-processed metadata
		* cdns.dat - List of content distribution networks
		* *_dmoz.db - DMOZ web directory data for site categorization
		* top500-sites.dat - Alexa top 500 sites
		* tracker-rules.dat - List of analytics/ad/tracking services
	* amazon-api.dat - API settings for bottlenose
	* cookies.py - Cookie library
	* form-data-regex.dat - Regular expressions for detecting personal data fields in forms
	* google\_analytics_cookie.py - Google analytics cookie parser
	* magic.mgc - Support file for bro (file format info)
	* processed-psl.dat - List of all domains under which people can register domains (used for validation)
		* https://publicsuffix.org
		* publicsuffix.py - Library for handling PSL data
	* sqlitedict.py - Database-backed Python dictionaries
* parsers/
	* BroLogParser.py - base class for Bro log parsing
	* *Parser.py - parser classes for individual Bro logs (see scripts/)
* scripts/ - Custom Bro scripts
	* cookie.bro - Records all cookies
	* html_titles.bro - Logs all titles from HTTP pages
	* http_form.bro - Logs all form data
	* http_info.bro - Logs HTTP info
	* private_browsing.bro - Logs pages visited under private browsing/"incognito mode" (semi-reliable heuristic)
	* regexes.bro - Extracts things from data matching certain regular expressions
* userdata/
	* userdata.py - Data container classes for various types of logged userdata
* analyze.py - Network trace analysis functions
* leakdetector.py - Runs Bro and generates trace JSON files for use in analyze.py.
* productinfo.py - Interfaces for looking up data about products from online retailers (used in analyze.py).
* servicemapper.py - Functions for mapping raw data to information about services (e.g. website categorization).
* utils.py - Various helper functions used in different scripts.

Other files:
* LICENSE - Attribution for files adapted from third parties.
* requirements.txt - List of Python required to use the project (readable by pip package manager)
* todo.md - Self explanatory. 
	
Running the scripts
-------------------
Capture data:
    
	python leakdetector.py -i en1 -o output-file.json
	# Replace `en1` with your network card. `en1` is Wi-Fi on OS X; en0 is Ethernet.

Process data:
	
	python analyze.py output-file.json processed.json

Data gathered
=============
What's working
--------------
  * Email addresses
    * All captured addresses
    * Personal emails with decent confidence 
  * Emails
    * Presence of email activity (e.g. “you sent or received an email today”) - for everyone
    * To/from/subject lines of emails - only for people who use unencrypted email servers (not Gmail)
  * Phone numbers 
    * What site the number was transmitted from
  * Usernames and passwords
    * Both in very specific situations - "HTTP basic authentication”, which is when your browser directly prompts you for username and password
      * Example: [nathanielfruchter.com/auth-test](http://nathanielfruchter.com/auth-test) 
      * Almost no websites use this any more so it’s kind of a giveaway, but we have it
  * Web history data
    * Private browsing history
      * The detection method for private browsing isn’t at 100%, so we can say a site was _probably_ visited with private browsing, but we can’t say 100%
    * Sites visited
      * Site category
      * Number of visits
      * First visit to site, latest visit to site - if site uses Google Analytics (this data is grabbed from cookies)
      * Domain names/subdomain names
      * Specific URLs and page contents - if not HTTPS
    * Form data
      * Raw contents of submitted forms on webpages - if not HTTPS
    * Site activity/site specific
      * General searches done on site (e.g. Bing, Google Scholar)
      * Product searches and product data (Amazon, eBay; can be extended to other sites with more work)
      * Wikipedia pages visited
      * Flight searches (Delta, United, Southwest, American)
        * United frequent flier ID 
    * Cookie data
      * Raw cookie data (pretty unreadable by human eyes)
    * Other data
      * Web page titles - if not HTTPS
      * Secure or not (whether the site was accessed using HTTPS)
      * Presence of tracking/advertisement cookies
  * System 
    * Computer OS
    * IP address
    * Location (IP address based)
    * Browser

Future possibilities
--------------------
  * Applications used
    * This would be based on how certain applications contact certain domains. So, iTunes communicates with a specific apple server —> guess person is using iTunes
  * Files downloaded (file names/size/etc, potentially the link to the file)
  * More confidence on personal info like name, address, phone number, etc.
    * This would be extracted from the form data that we have right now; just have to write something to look for common fields like first name, last name and do some matching.
    * Usernames
    * Plaintext passwords
  * Other useful bits of data like order numbers, tracking numbers, etc. 

