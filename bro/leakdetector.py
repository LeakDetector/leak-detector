#!/usr/bin/env python

import sys
import time
import os
import logging
import argparse
import utils
import subprocess
import signal
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

def run_bro(bro_args, logdir):
    global bro_proc

    # get absolute paths to our custom bro scripts
    bro_scripts = ''
    for script in BRO_SCRIPTS:
        bro_scripts += ' %s' % os.path.abspath(script)
    logging.getLogger(__name__).debug('Custom bro scripts: %s', bro_scripts)

    # change to logdir before running bro
    origdir = os.getcwd()
    os.chdir(logdir)

    # run bro
    brocmd = '%s %s %s' % (BRO, bro_args, bro_scripts)
    logging.getLogger(__name__).debug('Running bro in temp dir: %s', logdir)
    logging.getLogger(__name__).debug(brocmd)
    bro_proc = subprocess.Popen(brocmd.split())
    bro_proc.wait()
    #utils.check_output(brocmd)

    # change back to original dir
    logging.getLogger(__name__).debug('Switching back to dir: %s', origdir)
    os.chdir(origdir)


def kill_handler(signum, frame): 
    if bro_proc:
        bro_proc.terminate()
    

def main():
    
    # make a temp dir for bro logs if none was specified
    if not args.logdir:
        utils.init_temp_dir('bro_logs')
        logdir = utils.get_temp_dir('bro_logs')
    else:
        logdir = args.logdir
        if not os.path.isdir(logdir):
            try:
                os.makedirs(logdir)
            except Exception as e:
                logging.getLogger(__name__).error('Error creating logdir %s: %s', logdir, e)

    # leakdetector runs in one of three modes:
    # 1) run bro on a pcap trace and analyze the resulting logs
    # 2) run bro on live traffic and analyze the resulting logs
    # 3) analyze existing bro log files
    # TODO: interface has a default....
    if args.tracefile:
        logging.getLogger(__name__).info('Analyzing trace: %s', args.tracefile)
        run_bro('-r %s' % (args.tracefile), logdir)
    elif args.interface:
        logging.getLogger(__name__).info('Analyzing traffic on %s', args.interface)
        run_bro('-i %s' % (args.interface), logdir)
    elif args.logdir:
        logging.getLogger(__name__).info('Analyzing Bro logs in %s', args.logdir)
    else:
        logging.getLogger(__name__).warn('Must provide either a packet trace, an interface to sniff, or a directory of existing Bro logs.')
        sys.exit()
    
    analyze_logs(logdir)

    # remove bro log temp dir
    if not args.logdir:
        utils.remove_temp_dir('bro_logs')


if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze network traffic for leaked information')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print extra information for debugging.')
    parser.add_argument('-o', '--outfile', default=None, help='Save output JSON to a file instead of printing to terminal.')
    parser.add_argument('-r', '--tracefile', default=None, help='Analyze existing trace (PCAP file) instead of live traffic.')
    parser.add_argument('-f', '--filter', default=None, help='A CSV string of keys to include in the output. (Useful to limit output to subset of keys you care about.)')
    parser.add_argument('-l', '--logdir', default=None, help='Use the specified directory to store/read bro logs.')
    parser.add_argument('-i', '--interface', default='en0', help='Name of interface to sniff (use "ifconfig" to see options).')
    args = parser.parse_args()

    if args.tracefile:
        args.tracefile = os.path.abspath(args.tracefile)

    # set up signal handlers
    signal.signal(signal.SIGTERM, kill_handler)
    signal.signal(signal.SIGINT , kill_handler)

    # set up logging
    logging.basicConfig(
        #filename = fileName,
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno)s %(funcName) -26s %(message)s",
        level = logging.DEBUG if args.verbose else logging.WARNING
    )

    main()
