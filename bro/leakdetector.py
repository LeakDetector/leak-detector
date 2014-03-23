#!/usr/bin/env python

import sys
import time
import os
import logging
import argparse
import utils
from userdata import UserData
from HTTPLogParser import HTTPLogParser
from HTMLTitlesLogParser import HTMLTitlesLogParser
from DNSLogParser import DNSLogParser


BRO = '/usr/bin/env bro'

# which bro logs do we want to parse? dict maps log file name to parser to
# process it with.
BRO_LOGS = {
    'http.log': HTTPLogParser,
    'html_titles.log': HTMLTitlesLogParser,
    'dns.log': DNSLogParser
}

def analyze_logs(log_dir):
    userdata = UserData()

    for log, parser_class in BRO_LOGS.iteritems():
        log_path = os.path.join(log_dir, log)
        if os.path.isfile(log_path):
            parser = BRO_LOGS[log](log_path)
            parser.analyze()
            userdata.merge(UserData(parser.data))


    print userdata

    

def main():

    # TEST CODE
    analyze_logs('./scripts')


    if args.tracefile:
        pass
    else:
        pass



if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze network traffic for leaked information')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print extra information for debugging.')
    parser.add_argument('-o', '--outfile', default=None, help='Save output JSON to a file instead of printing to terminal.')
    parser.add_argument('-r', '--tracefile', default=None, help='Analyze existing trace (PCAP file) instead of live traffic.')
    args = parser.parse_args()

    # set up logging
    logging.basicConfig(
        #filename = fileName,
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno)s %(funcName) -26s %(message)s",
        level = logging.DEBUG if args.verbose else logging.WARNING
    )

    main()
