#!/usr/bin/env python

import leakdetector.leakdetector as ld
import argparse
import os
import datetime

if __name__ == '__main__':
    """Command line entry point to run leak detector."""
    
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze network traffic for leaked information')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print extra information for debugging.')
    parser.add_argument('-o', '--outfile', default=None, help='Save output JSON to a file instead of printing to terminal.')
    parser.add_argument('-r', '--tracefile', default=None, help='Analyze existing trace (PCAP file) instead of live traffic.')
    parser.add_argument('-f', '--filter', default=None, help='A CSV string of keys to include in the output. (Useful to limit output to subset of keys you care about.)')
    parser.add_argument('-l', '--logdir', default=None, help='Use the specified directory to store/read bro logs.')
    parser.add_argument('-i', '--interface', default='en1', help='Name of interface to sniff (use "ifconfig" to see options).')
#   parser.add_argument('-t', '--analyzeinterval', type=int, default=5, help='When running in live mode, how often to analyze Bro logs? (seconds)')
    args = parser.parse_args()

    if not args.outfile:
        now = datetime.datetime.now().isoformat("_").replace(":", "_").replace(".", "_")
        outfile = "leakdetector-output-%s" % now + ".json"
    else:
        outfile = args.outfile + ".json"  

    here = os.path.dirname(os.path.realpath(__file__))
    outfile = os.path.join(here, outfile)
        
        
    # Run
    ld.main(args.interface, outfile=outfile, tracefile=args.tracefile, _filter=args.filter, logdir=args.logdir, verbose=args.verbose)
    print outfile
