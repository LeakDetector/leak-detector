#!/usr/bin/env python

import sys
import time
import os
import logging
import argparse
import utils
import subprocess
import signal
import glob

# Leak detector specific
from userdata.userdata import UserData
import parsers

# Get absolute script path for includes
try:
    here = os.path.dirname(os.path.realpath(__file__))
except NameError:
    here = os.path.curdir + os.path.sep

BRO = '/usr/bin/env bro'
BRO_SCRIPTS = glob.glob(os.path.join(here, "scripts/*.bro"))

# Which bro logs do we want to parse?
# Maps log name to corresponding parser class
BRO_LOGS = {
    'http.log': parsers.HTTPLogParser,
    'html_titles.log': parsers.HTMLTitlesLogParser,
    'dns.log': parsers.DNSLogParser,
    'regexes.log': parsers.RegexesLogParser,
    'private_browsing.log': parsers.PBLogParser,
    'ssl.log': parsers.SSLLogParser,
    'http_form.log': parsers.FormLogParser,
    'cookie.log': parsers.CookieLogParser,
    'http_info.log': parsers.HTTPInfoLogParser,
    'smtp.log': parsers.SMTPLogParser
}

def analyze_logs(log_dir, _filter=None, outfile=None):
    """Analyze logs generated by Bro given a `log_dir`. Uses classes defined in
    `BRO_LOGS` to map parser classes to filenames."""

    userdata = UserData()
    if _filter:
        userdata.set_output_filter(_filter)

    for log, parser_class in BRO_LOGS.iteritems():
        log_path = os.path.join(log_dir, log)
        if os.path.isfile(log_path):
            parser = BRO_LOGS[log](log_path)
            parser.analyze()
            userdata.merge(UserData(parser.data))

    if outfile:
        try:
            with open(outfile, 'w') as f:
                f.write(userdata.json)
            f.closed
        except Exception as e:
            logging.getLogger(__name__).error(e)
    else:
        print userdata

def run_bro(bro_args, logdir):
    """Run the bro process with arguments `bro_args`, storing logs in `logdir`."""
    global bro_proc

    # Get absolute paths to our custom bro scripts
    bro_scripts = ''
    for script in BRO_SCRIPTS:
        bro_scripts += ' %s' % os.path.abspath(script)
    logging.getLogger(__name__).debug('Custom bro scripts: %s', bro_scripts)

    # Change to logdir before running bro
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
    """Kill bro."""
    if bro_proc:
        bro_proc.terminate()

def main(interface, outfile=None, tracefile=None, _filter=None, logdir=None, verbose=False):
    """Main function to run from command line."""
    
    if tracefile:
        tracefile = os.path.abspath(tracefile)

    # Set up signal handlers
    signal.signal(signal.SIGTERM, kill_handler)
    signal.signal(signal.SIGINT, kill_handler)

    # Set up logging
    logging.basicConfig(
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno)s %(funcName) -26s %(message)s",
        level = logging.DEBUG if verbose else logging.WARNING
    )    
    

    # make a temp dir for bro logs if none was specified
    if not logdir:
        utils.init_temp_dir('bro_logs')
        logdir = utils.get_temp_dir('bro_logs')
    else:
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
    
    if tracefile:
        logging.getLogger(__name__).info('Analyzing trace: %s', tracefile)
        run_bro('-r %s' % (tracefile), logdir)
    elif interface:
        logging.getLogger(__name__).info('Analyzing traffic on %s', interface)
        run_bro('-i %s' % (interface), logdir)
    elif logdir:
        logging.getLogger(__name__).info('Analyzing Bro logs in %s', logdir)
    else:
        logging.getLogger(__name__).warn('Must provide either a packet trace, an interface to sniff, or a directory of existing Bro logs.')
        sys.exit()
    
    analyze_logs(logdir, _filter=_filter, outfile=outfile)

    # remove bro log temp dir
    if not logdir:
        utils.remove_temp_dir('bro_logs')

def commandline():
    """Command line entry point to run leak detector."""
    
    global args
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze network traffic for leaked information')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print extra information for debugging.')
    parser.add_argument('-o', '--outfile', default=None, help='Save output JSON to a file instead of printing to terminal.')
    parser.add_argument('-r', '--tracefile', default=None, help='Analyze existing trace (PCAP file) instead of live traffic.')
    parser.add_argument('-f', '--filter', default=None, help='A CSV string of keys to include in the output. (Useful to limit output to subset of keys you care about.)')
    parser.add_argument('-l', '--logdir', default=None, help='Use the specified directory to store/read bro logs.')
    parser.add_argument('-i', '--interface', default='en1', help='Name of interface to sniff (use "ifconfig" to see options).')
    args = parser.parse_args()

 
    # Run
    main(args.interface, outfile=args.outfile, tracefile=args.tracefile, _filter=args.filter, logdir=args.logdir, verbose=args.verbose)

if __name__ == '__main__':
    commandline()

