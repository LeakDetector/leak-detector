#!/usr/bin/env python

import sys
import time
import os
import logging
import argparse
import utils
import subprocess
import multiprocessing
import signal
import glob

# Leak detector specific
from userdata.userdata import UserData
from utils import ThreadStop
import parsers
import analyze

# Get absolute script path for includes
try:
    here = os.path.dirname(os.path.realpath(__file__))
except NameError:
    here = os.path.curdir + os.path.sep

BRO = '/usr/bin/env bro'
BRO_SCRIPTS = glob.glob(os.path.join("\"" + here + "\"", "scripts/*.bro"))

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
    # 'http_info.log': parsers.HTTPInfoLogParser,
    'smtp.log': parsers.SMTPLogParser
}

def analyze_logs(log_dir, _filter=None, outfile=None, userdata=None):
    """Analyze logs generated by Bro given a `log_dir`. Uses classes defined in
    `BRO_LOGS` to map parser classes to filenames."""

    if not userdata: userdata = UserData()
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

class LiveLogAnalyzer(ThreadStop):
    def __init__(self, log_dir, analyze_interval, outfile):
        self.log_dir = log_dir
        self.analyze_interval = analyze_interval
        self.outfile = outfile
        super(LiveLogAnalyzer, self).__init__()

    def run(self):
        while self.runningFlag.isSet():
            time.sleep(self.analyze_interval)
            analyze_logs(self.log_dir, outfile=self.outfile)
            analyze.main(self.outfile, "%s.analyzed"%self.outfile)           

def run_bro(bro_args, logdir):
    """Run the bro process with arguments `bro_args`, storing logs in `logdir`."""
    global bro_proc
    global log_proc
    
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
    print brocmd
    bro_proc = subprocess.Popen(brocmd.split())
        
    # change back to original dir
    logging.getLogger(__name__).debug('Switching back to dir: %s', origdir)
    os.chdir(origdir)
    bro_proc.wait()


def monitor(interface, outfile=None, verbose=None, sniff=None):
    tracefile = os.path.abspath("ld-pcap-dec.pcap")
    
    def kill_handler(signum, frame):
        """Kill tcpdump and then analyze pcap."""
        if tcpdump_proc:
            tcpdump_proc.terminate()
        
        # Analyze pcap with bro
        run_bro('-r %s' % (tracefile), logdir)
        analyze_logs(logdir, outfile=outfile)

        # Now run leak detector
        print "Analyzing captured network traffic"
        utils.remove_temp_dir('bro_logs')
        analyze.main(outfile, "%s.analyzed" % outfile)        
        
    signal.signal(signal.SIGTERM, kill_handler)
    signal.signal(signal.SIGINT, kill_handler)

    logging.basicConfig(
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno)s %(funcName) -26s %(message)s",
        level = logging.DEBUG if verbose else logging.WARNING
    )    
    
    # Make log directory for bro
    utils.init_temp_dir('bro_logs')
    logdir = utils.get_temp_dir('bro_logs')
        
    # run sniff.sh
    # tcpdump_proc = subprocess.Popen(["sleep", "256"]) testing
    if sniff:
        tcpdump_proc = subprocess.Popen(["bash", "sniff.sh", interface])
    else:    
        tcpdump_proc = subprocess.Popen(['tcpdump', '-i', interface, '-w', tracefile])
    tcpdump_proc.wait()
    
    logging.getLogger(__name__).info('Analyzing trace: %s', tracefile)

def main(interface, outfile=None, tracefile=None, analyzeinterval=None, _filter=None, logdir=None, verbose=False, stdout=False):
    """Main function to run from command line."""
    def kill_handler(signum, frame): 
        """Kill bro."""
        logging.info('Exiting...')
        global bro_proc
        global log_proc

        if bro_proc:
            bro_proc.terminate()

        if not logdir:
            utils.remove_temp_dir('bro_logs')
            
        analyze_logs(logdir, outfile=outfile)
                        
        print "Analyzing captured network traffic (this may take a second...)"
        analyze.main(outfile, "%s.analyzed"%outfile)
            
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

    if tracefile:
        logging.getLogger(__name__).info('Analyzing trace: %s', tracefile)
        run_bro('-r %s' % (tracefile), logdir)
        analyze_logs(logdir, outfile=outfile)
    elif interface:
        logging.getLogger(__name__).info('Analyzing traffic on %s', interface)
        if analyzeinterval:
            analyze_thread = LiveLogAnalyzer(logdir, analyzeinterval, outfile)
            analyze_thread.start()
            run_bro('-i %s' % (interface), logdir)
            analyze_thread.stop()
        else:
            run_bro('-i %s' % (interface), logdir)
            analyze_logs(logdir, outfile=outfile)    
    elif logdir:
        logging.getLogger(__name__).info('Analyzing Bro logs in %s', logdir)
        analyze_logs(logdir, outfile=outfile)
    else:
        logging.getLogger(__name__).warn('Must provide either a packet trace, an interface to sniff, or a directory of existing Bro logs.')
        sys.exit()
    
