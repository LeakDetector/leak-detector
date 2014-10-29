#!/usr/bin/env python

from __future__ import print_function

import leakdetector.leakdetector as ld
import plaintext_summary as summary

import argparse
import os
import multiprocessing
import threading
import time

def clear(): os.system("clear")

if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze network traffic for leaked information (demo).')
    parser.add_argument('-o', '--outfile', default="LDDEMO", help='Save output JSON to a file instead of printing to terminal.')
    parser.add_argument('-i', '--interface', default='en1', help='Name of interface to sniff (use "ifconfig" to see options).')
#   parser.add_argument('-t', '--analyzeinterval', type=int, default=5, help='When running in live mode, how often to analyze Bro logs? (seconds)')
    args = parser.parse_args()
    
    if args.outfile:
        here = os.path.dirname(os.path.realpath(__file__))
        outfile = os.path.join(here, args.outfile)
    else:
        outfile = args.outfile    
    
    clear()
    ld.main(args.interface, outfile=outfile)
    clear()
    print(summary.parse("%s.analyzed" % outfile))
