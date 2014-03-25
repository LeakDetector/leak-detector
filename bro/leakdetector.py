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
from RegexesLogParser import RegexesLogParser


BRO = '/usr/bin/env bro'
BRO_SCRIPTS = ['scripts/html_titles.bro', 'scripts/regexes.bro']

# which bro logs do we want to parse?
# maps log name to corresponding parser class
BRO_LOGS = {
    'http.log': HTTPLogParser,
    'html_titles.log': HTMLTitlesLogParser,
    'dns.log': DNSLogParser,
    'regexes.log': RegexesLogParser
}


def analyze_logs(log_dir):
    userdata = UserData()
    if args.filter:
        userdata.set_output_filter(args.filter)

    for log, parser_class in BRO_LOGS.iteritems():
        log_path = os.path.join(log_dir, log)
        if os.path.isfile(log_path):
            parser = BRO_LOGS[log](log_path)
            parser.analyze()
            userdata.merge(UserData(parser.data))

    if args.outfile:
        try:
            with open(args.outfile, 'w') as f:
                f.write(userdata.json)
            f.closed
        except Exception as e:
            logging.getLogger(__name__).error(e)
    else:
        print userdata

    

def main():

    if args.tracefile:
        logging.getLogger(__name__).info('Analyzing trace: %s', args.tracefile)
        
        # get absolute paths to our custom bro scripts
        bro_scripts = ''
        for script in BRO_SCRIPTS:
            bro_scripts += ' %s' % os.path.abspath(script)
        logging.getLogger(__name__).debug('Custom bro scripts: %s', bro_scripts)

        # make a temp dir for bro logs
        utils.init_temp_dir('bro_logs')
        logdir = utils.get_temp_dir('bro_logs')

        # change to logdir before running bro
        origdir = os.getcwd()
        os.chdir(logdir)

        # run bro
        logging.getLogger(__name__).debug('Running bro in temp dir: %s', logdir)
        utils.check_output('%s -r %s %s' % (BRO, args.tracefile, bro_scripts))

        # change back to original dir and process logs
        logging.getLogger(__name__).debug('Switching back to dir: %s', origdir)
        os.chdir(origdir)
        analyze_logs(logdir)

        # remove bro log temp dir
        utils.remove_temp_dir('bro_logs')

    else:
        pass



if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze network traffic for leaked information')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print extra information for debugging.')
    parser.add_argument('-o', '--outfile', default=None, help='Save output JSON to a file instead of printing to terminal.')
    parser.add_argument('-r', '--tracefile', default=None, help='Analyze existing trace (PCAP file) instead of live traffic.')
    parser.add_argument('-f', '--filter', default=None, help='A CSV string of keys to include in the output. (Useful to limit output to subset of keys you care about.)')
    args = parser.parse_args()

    if args.tracefile:
        args.tracefile = os.path.abspath(args.tracefile)

    # set up logging
    logging.basicConfig(
        #filename = fileName,
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno)s %(funcName) -26s %(message)s",
        level = logging.DEBUG if args.verbose else logging.WARNING
    )

    main()
