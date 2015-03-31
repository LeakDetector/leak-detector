Outline of keys and values in output
------------------------------------

* `history`: The parent key for things involving web / browsing history.
	* `domains`: A list of dictionaries. Each dictionary represents an individual site.
		* `category`: Most domains have a category (if it was possible to automatically categorize it).
		* `description`: Currently a blank field.
		* `domains`: A list of domains associated with this site. Some sites will have one domain in this list, but others will have multiple. For example, if a user browses to Blackboard, you might see both "cmu.edu" and "blackboard.cmu.edu" in this list.
			* Each domain is a list broken up into the component parts of the domain (imagine separating on the dot). For example `['www', 'cmu', 'edu']`.
		* `hits`: The number of requests sent to this domain.
		* `name`: A best guess at the base domain. If a name can be found, this is a human readable name ("Amazon"), otherwise it's the domain ('amazon.com').
		* `secure`: True if HTTPS was used.
		* `formdata`: A list of lists that contains
			* The domain (element 0), the page name submitted from (element 1), and a dictionary (element 2), which contains:
				* Key-value pairs that map to the form field names and contents submitted
		* `maybe_private_browsing`: True if the private browsing heuristic says yes
		* `queries`: A list of search queries.
	* `page-titles`: A list of scraped web page titles (specifically, anything between two `<title>` tags in captured HTML source).
	* `raw-history`: A sorted, time-stamped list of pages and files loaded.
		* Each element in this list consists of a base domain, a request path, and a UNIX timestamp.
	* `special-sites`: A list of special (for lack of a better term) websites that we have extra processing for. So, Amazon would fit in here because we have the special shopping data lookup coded into the program.
		* Can contain all of the things under `domains`, plus custom elements for each site.
		* Right now, `products` and `queries` are the only special data surfaced. For a full list, look at `leakdetector/config/analysis.py` and the `extractors` variable. This variable defines all of the special lookup code used right now. For example, you can see Amazon uses regular expression matching, references a function for looking up product data from the product ID number, and outputs to an attribute called `products`.
* `email`: Emails extracted from the data stream.
* `files`: Empty for now.
* `system`: Information related to the network connection and machine.
	* `browser`: Names of browsers that were detected as being used.
	* `location`: The city and zipcode level location of the IP address of machine(s).
	* `os`: The OS version.
* `personal-info` 
	* `personal-email`: Emails that meet the 'is personal email' heuristic.
	* `phone`: Strings that match a phone number regex (unreliable for now).
