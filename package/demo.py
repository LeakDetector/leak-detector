import json
import random
import urllib

def formatList(l):
    if l:
        return ", ".join(l)
    else:
        return "no info"
        
def bullets(l):
    output = "\n"
    for item in l:
        output += "\t* %s\n" % item 
    
    return output
    
def indent(l, level=1):
    return ["%s%s" % ("\t"*level, line) for line in l]
    
def formatDomain(site):
    output = []
    
    mainInfo = (site['name'], ".".join(site['domains'][0]), site['hits'])
    category = " > ".join(site['category']).replace("_", " ") if type(site['category']) is list else site['category']
    output.append("* %s [%s] -  %s request(s)" % mainInfo)
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
    return len([site for site in section if site.get(key)])

def header(name):
    return "\n%s\n%s\n" % (name, "="*len(name))

def parse(jsonfile):        
    if type(jsonfile) is not file:
        with open(jsonfile) as f:
            analysis = json.load(f)
    else: 
        analysis = json.load(jsonfile)   

    output = []
    
    if analysis.get('system'):
        # System info
        browsers = analysis['system'].get('browser')
        location = analysis['system'].get('location')
        os = analysis['system'].get('os')
    
        output.append(header("System information"))
        output.append("* Browsers used: %s" % formatList(browsers))
        output.append("* Operating system: %s" % formatList(os))
        output.append("* Your location: %s" % formatList(location))
    
    # Web history
    if analysis.get('history'):
        output.append(header("Web history"))
        
        if analysis['history'].get('page-titles'):
            titles = [urllib.unquote(t) for t in analysis['history']['page-titles'] if len(t) > 15 and "document.title" not in t]
            titles = random.sample(titles, len(titles)/2)
            output.append("* Here are some pages you visited: %s" % bullets(titles))
            
        if analysis['history'].get('domains'):
            domains = [site for site in analysis['history']['domains'] if site['category'] is not None]
            output.append("* Here are some sites that you (or your browser) visited: ")
    
            for site in domains:
                [output.append(line) for line in indent(formatDomain(site))]
    
    if analysis.get('services'):        
        for site in analysis['services']:
            [output.append(line) for line in formatDomain(site)]
            
    if analysis.get('personal-info'):
        output.append(header("Contact information"))
        
        if analysis['personal-info'].get('phone'):
            phones = analysis['personal-info']['phone']
            phones = random.sample(phones, len(phones)/2)
            output.append("* Some phone numbers on pages you viewed: %s" % bullets(phones) )
        
        if analysis['personal-info'].get('personal-email'):
            output.append("* Emails on pages you viewed: %s" % formatList(analysis['personal-info']['personal-email']) )
            
    if analysis.get('email-activity'):
        output.append(header("Other information"))
        
        if analysis.get('email-activity'):
            output.append("* Email activity: %s" % analysis['email-activity'])
            

    output.append(header("Summary statistics:"))
    
    if analysis['history'].get('domains'):
        n_domains = len(analysis['history']['domains'])
    if analysis['history'].get('page-titles'):
        n_titles = len(analysis['history']['page-titles'])
        
    domainstats = ("no" or n_domains, "no" or n_titles)
    output.append("\t * %s domains visited - %s page titles captured" % domainstats)
    
    n_pb = domainStat(analysis['history']['domains'], 'maybe_private_browsing')
    n_https = domainStat(analysis['history']['domains'], 'secure')
    n_form = domainStat(analysis['history']['domains'], 'formdata')
    n_tracking = domainStat(analysis['history']['domains'], 'tracking')

    output.append("\t * %s private browsing requests, %s sites with HTTPS, %s sites with trackers" % (n_pb, n_https, n_tracking))
    output.append("\t * %s forms captured" % n_form)
        
    return "\n".join(output)
    
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Display Leak Detector results as plain text.')

    parser.add_argument('-i', metavar="in-file", type=argparse.FileType('r'), required=True)
    try: 
        args = parser.parse_args()
        print parse(args.i)
    except IOError, msg:
        parser.error(str(msg))    

        