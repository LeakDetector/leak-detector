Leak Detector 
==============

This is the source for the Bro log based version of the leak detector backend.  

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
* 
	
Running the scripts
-------------------
Capture data and return intermediate and processed data:
  
	python record-trace.py -i en1 -o filename
	# Replace `en1` with your network card. `en1` is Wi-Fi on OS X if you also have an ethernet port

Just process intermediate data:
	
	python analyze-trace.py input-filename.json analyzed-output-filename.json

Programatically running LD
--------------------------
There should be no need to directly run `leakdetector.py` in the `leakdetector/` folder. If you want to directly start and stop from a Python script, you can import the module and control it that way (see `record-trace.py` for an example).

If you want to programatically start LD, you can do so by importing. For example:
	
	import leakdetector.leakdetector as ld
	ld.main("en1", outfile="example-trace")
	
Note that ending this recording session will still require a ctrl-c to kill the LD process looping in the background. If you want to automatically stop it with no user intervention, I would recommend forking the `ld.main` call into a subprocess and then killing it through Python. 

	import multiprocessing, os, time
	proc = multiprocessing.Process(target=lambda: ld.main("en1", outfile="example-trace.json"))

	# Start for 30 seconds
	proc.start()
	time.sleep(30)
	
	# Stop
	proc.terminate()
	
	# Wait for processing to finish
	while True:
		if os.path.exists("example-trace.json"):
			p.join()
			break
	
	# Now do other stuff
	...
	
	
	
	
	

