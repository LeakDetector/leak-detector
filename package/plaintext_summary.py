import json
import random
import urllib

def formatList(l):
    """Join a list of with commas."""
    
    if l:
        return ", ".join(l)
    else:
        return "no info"
        
def bullets(l):
    """Add bullets to lines of text."""
    
    output = "\n"
    for item in l:
        output += "\t* %s\n" % item 
    
    return output
    
def indent(l, n=1):
    """Add `n` tabs to the beginning of each line."""
    
    return ["%s%s" % ("\t"*n, line) for line in l]
    
def formatDomain(site):
    """Create a block text given the dictionary for a certain domain."""
    
    output = []
    
    mainInfo = (site['name'], ".".join(site['domains'][0]), site['hits'])
    output.append("* %s [%s] -  %s request(s)" % mainInfo)

    if site.get('category'):
        if "World" not in site.get('category'):
            category = " > ".join(site['category']).replace("_", " ") if type(site['category']) is list else site['category']
            output.append("\t * In category: %s" % urllib.unquote(category))

    if site.get('prev_visit'):
        output.append("\t * Last visited by you on %s" % site.get('prev_visit'))
        
    if site.get('flights'):
        output.append("\t * Site-specific information: %s" % site.get('flights'))
        
    if site.get('queries'):
        output.append("\t * Searches on this site: %s" % formatList(site.get('queries')))
    
    if site.get('products'):
        products = ["%s ($%s)" % (prod['name'], prod['price']) for prod in site.get('products') if prod]
        output.append("\t * Products viewed: %s" % formatList(products))
        
    if site.get('tracking'):
        output.append("\t * This site uses analytics or tracking code")
        
    if site.get('secure'):
        output.append("\t * This site is secure and uses HTTPS")
        
    if site.get('formdata'):
        output.append("\t * Data was captured from one or more forms submitted on this site")
        
    if site.get('maybe_private_browsing'):
        output.append("\t * You may have viewed this site using private browsing mode")
    
    output.append("")
    
    return output
    
def domainStat(section, key):
    """Return the number of dictionaries with `key` in a list of dictionaries `section`."""
    
    return len([site for site in section if site.get(key)])

def header(name):
    """Return a markdown header."""
    
    return "\n%s\n%s\n" % (name, "="*len(name))

def parse(jsonfile, sections="all"):            
    # Open and read the file
    if type(jsonfile) is not file:
        with open(jsonfile) as f:
            analysis = json.load(f)
    else: 
        analysis = json.load(jsonfile)   
    
    def system():    
        output = []    
        ## System info
        if analysis.get('system'):
            # System info
            browsers = analysis['system'].get('browser')
            location = analysis['system'].get('location')
            os = analysis['system'].get('os')
    
            output.append(header("System information"))
            output.append("* Browsers used: %s" % formatList(browsers))
            output.append("* Operating system: %s" % formatList(os))
            output.append("* Your location: %s" % formatList(location))
        
        return output            
    
    ## Web history
    def history():
        output = []
        
        if analysis.get('history'):
            output.append(header("Web history"))

            if analysis['history'].get('page-titles'):
                titles = [urllib.unquote(t) for t in analysis['history']['page-titles'] if "document.title" not in t and len(t) > 10]
                output.append("* Here are some pages you or your browser requested: %s" % bullets(titles))
            
            if analysis['history'].get('domains'):
                domains = [site for site in analysis['history']['domains']]
                output.append("* Here are some sites that you (or your browser) requested: ")
    
                for site in domains:
                    [output.append(line) for line in indent(formatDomain(site))]

        if analysis.get('services'):        
            for site in analysis['services']:
                [output.append(line) for line in indent(formatDomain(site))]
        
        return output               
        
    ## Products
    def products():
        output = []
        sites = False
        
        if analysis.get('history') and analysis.get('services'):
            sites = analysis['history']['domains'] + analysis['services']
        elif analysis.get('history') and not analysis.get('services'):
            sites = analysis['history']['domains']
        elif analysis.get('services') and not analysis.get('history'):
            sites = analysis['services']
        
        if sites:            
            sites = [site for site in sites if site.get('queries') or site.get('products')]    
            
            for site in sites:
                [output.append(line) for line in indent(formatDomain(site))]
            
            return output    
                
    ## Emails, phone numbers
    def personalinfo():
        output = []
        
        if analysis.get('personal-info'):
            output.append(header("Contact information"))
        
            if analysis['personal-info'].get('phone'):
                phones = analysis['personal-info']['phone']
                phones = random.sample(phones, len(phones)/2)
                output.append("* Some phone numbers on pages you viewed: %s" % bullets(phones) )
        
            if analysis['personal-info'].get('personal-email'):
                emails = [text for user, domain, text in analysis['personal-info']['personal-email']]
                output.append("* Personal email addresses on pages you viewed: %s" % bullets(emails))
            
        if analysis.get('email-activity'):
            output.append(header("Other information"))
        
            if analysis.get('email-activity'):
                output.append("* Email activity: %s" % analysis['email-activity'])

        return output        
            
    ## Statistics
    def stats():
        output = []
        if analysis.get('history'):
            output.append(header("Summary statistics:"))
    
            domainstats = ("No", "No")
            if analysis['history'].get('domains'):
                n_domains = len(analysis['history']['domains'])
            if analysis['history'].get('page-titles'):
                n_titles = len(analysis['history']['page-titles'])
            
            domainstats = (n_domains, n_titles)
            output.append("\t * %s domains requested - %s page titles captured" % domainstats)
    
            n_pb = domainStat(analysis['history']['domains'], 'maybe_private_browsing')
            n_https = domainStat(analysis['history']['domains'], 'secure')
            n_form = domainStat(analysis['history']['domains'], 'formdata')
            n_tracking = domainStat(analysis['history']['domains'], 'tracking')

            output.append("\t * %s private browsing requests, %s sites with HTTPS, %s sites with trackers" % (n_pb, n_https, n_tracking))
            output.append("\t * %s forms captured" % n_form)
        
            return output        
        
    ## Return text block    
    if sections == "all":
        summary = [system(), history(), personalinfo(), stats()]
    elif type(sections) in [list, tuple]:
        summary = [locals()[fn]() for fn in sections]
    
    if summary and any(summary):
        summary = reduce(list.__add__, summary)    
        return "\n".join(summary).encode('utf-8')
    
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Display Leak Detector results as plain text.')

    parser.add_argument('i', metavar="analyzedfile")
    
    try:
        # Parse and print the file
        args = parser.parse_args()
        print parse(args.i)
    except IOError, msg:
        # Or print what went wrong
        parser.error(str(msg))


        