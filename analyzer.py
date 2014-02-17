#!/usr/bin/env python

import sys
import os
import shutil
import logging
import re
from pcap import *
from optparse import OptionParser
from userstats import *
from TCPAnalyzer import *
#from HttpConversationParser import *
from PacketStreamAnalyzer import *
from HTMLAnalyzer import *
import utils
from PIL import Image


# Setup command line options
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Prints extra information useful for debugging.")


def filter(packet):
    return True

def do_display_image(filename):
    """Decide if an image should be displayed to user or not.

    Skip images smaller than 150px in either dimension or which contain fewer
    than 10 distinct colors.
    """

    try:
        im = Image.open(filename)
        width, height = im.size
        if width < 150 or height < 150:
            return False

        colors = im.getcolors(10)  # returns None if there are more than 10 colors
        if colors:
            return False

        return True
    except Exception, e:
        logging.getLogger(__name__).warning('Error processing image: %s', e)
    

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

    # process HTML pages
    for html_file in t.html_files:
        with open(html_file, 'r') as f:
            html = f.read()
            ha = HTMLAnalyzer(html)
            stats.update_page_titles( ha.page_titles )
            stats.update_amazon_products( ha.amazon_products )
        f.closed

    # save images to temp dir
    for image in t.images:
        if do_display_image(image):
            new_image_path = os.path.join(utils.get_temp_dir('images'),\
                            os.path.basename(image))
            shutil.copyfile(image, new_image_path)
            stats.update_image_paths( set([new_image_path]) )

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
