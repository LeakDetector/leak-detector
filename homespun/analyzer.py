#!/usr/bin/env python

import sys
import os
import shutil
from pcap import *
from userstats import *
from TCPAnalyzer import *
from PacketStreamAnalyzer import *
from HTMLAnalyzer import *
import utils
from PIL import Image


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

    # look for regex matches
    regexes = {}   #{'Phone Number':[r'\(?[2-9][0-8][0-9]\s*\W?\s*[2-9][0-9]{2}\s*\W?\s*[0-9]{4}']}
    for s in t.streams:
        match_dict = s.find_regexes(regexes)
        stats.update_matched_regexes(match_dict)

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
