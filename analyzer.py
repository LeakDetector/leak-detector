import sys
import os
import logging
import re
from pcap import *
from optparse import OptionParser
from userstats import *
from TCPAnalyzer import *
from HttpConversationParser import *
from PacketStreamAnalyzer import *
from HTMLAnalyzer import *
import utils


# Setup command line options
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Prints extra information useful for debugging.")


def filter(packet):
    return True
    

def analyze_trace(trace, stats):
    ##
    ## STEP ONE: Analyze individual packets
    ##
    logging.getLogger(__name__).info('Analyzing individual packets...')
    p = PacketStreamAnalyzer()
    try:
        # Create PCap object
        # Offline network capture
        listener = OfflineNetworkCapture(trace)

    except (PCapPermissionDeniedException,PCapInvalidNetworkAdapter), e:
        logging.getLogger(__name__).error(e)
        sys.exit(1)
        


    # Process packet trace
    try:
        for packet in listener.get_packets(filter):
            p.update(packet)
    except (KeyboardInterrupt, SystemExit), e:
         sys.exit()
    finally:
        listener.close()

    # Updated user stats
    stats.update_os(p.os)
    stats.update_languages(p.languages)
    stats.update_browsers(p.browsers)
    stats.update_visited_domains(p.visited_domains)
    stats.update_visited_subdomains(p.visited_subdomains)
    stats.update_google_queries(p.google_queries)
    stats.update_email_servers(p.email_servers)



    ##
    ## STEP TWO: Analyze TCP streams
    ##
    logging.getLogger(__name__).info('Analyzing TCP streams...')
    utils.init_temp_dir('tcpflow')
    t = TCPAnalyzer(trace)

    logging.getLogger(__name__).info('Analyzing HTTP conversations...')
    # Don't waste time reconstructing HTTP conversations that don't contain HTML
    html_streams = []
    for s in p.tcp_html_streams:
        sinfo = s.split(',')
        html_streams += [st for st in t.http_streams if sinfo[0] in st.ip_addresses and sinfo[2] in st.ip_addresses and int(sinfo[1]) in st.ports and int(sinfo[3]) in st.ports]

    for html_stream in html_streams:
        logging.getLogger(__name__).info('    Analyzing stream: %s', html_stream)
        parser = HttpConversationParser(html_stream.http_data)

        # process HTML pages
        for page in parser.html_pages:
            ha = HTMLAnalyzer(page)
            stats.update_page_titles( ha.page_titles )
            stats.update_amazon_products( ha.amazon_products )

        # save images to temp dir
        parser.save_images_to_dir(utils.get_temp_dir('images'))

    utils.remove_temp_dir('tcpflow')

    return stats
        



def main(options, args):
    # set up logging
    logging.basicConfig(
        #filename = fileName,
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno)s %(funcName) -26s %(message)s",
        level = logging.DEBUG if options.verbose else logging.WARNING
    )

    # delete existing images if we're running analyzer as standalone
    utils.init_temp_dir('images')

    trace = args[0]
    stats = UserStats()

    stats = analyze_trace(trace, stats)
    print stats.json


if __name__ == '__main__':
    (options, args) = parser.parse_args()
    sys.exit(main(options, args))
